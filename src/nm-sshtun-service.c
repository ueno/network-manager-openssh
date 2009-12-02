/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* nm-sshtun-service - sshtun integration with NetworkManager
 *
 * Copyright (C) 2005 - 2008 Tim Niemueller <tim@niemueller.de>
 * Copyright (C) 2005 - 2008 Dan Williams <dcbw@redhat.com>
 * Copyright (C) 2009 Daiki Ueno <ueno@unixuser.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * $Id: nm-openvpn-service.c 4232 2008-10-29 09:13:40Z tambeti $
 *
 */


#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <glib/gi18n.h>
#include <dbus/dbus.h>
#include <dbus/dbus-glib-lowlevel.h>
#include <dbus/dbus-glib.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>

#include <NetworkManager.h>
#include <NetworkManagerVPN.h>
#include <nm-setting-vpn.h>

#include "nm-sshtun-service.h"
#include "nm-utils.h"
#include "sshtun.h"

G_DEFINE_TYPE (NMSshtunPlugin, nm_sshtun_plugin, NM_TYPE_VPN_PLUGIN)

#define NM_SSHTUN_PLUGIN_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_SSHTUN_PLUGIN, NMSshtunPluginPrivate))

typedef struct {
	sshtun_handle_t handle;
	guint send_ip4_config_timeout;
} NMSshtunPluginPrivate;

typedef struct {
	const char *name;
	GType type;
	gint int_min;
	gint int_max;
} ValidProperty;

static ValidProperty valid_properties[] = {
	{ NM_SSHTUN_KEY_TUN_USE_TAP,          G_TYPE_BOOLEAN, 0, 0 },
	{ NM_SSHTUN_KEY_CONFIG_SCRIPT,        G_TYPE_STRING, 0, 0 },
	{ NM_SSHTUN_KEY_USER,                 G_TYPE_STRING, 0, 0 },
	{ NM_SSHTUN_KEY_HOST,                 G_TYPE_STRING, 0, 0 },
	{ NM_SSHTUN_KEY_PUBLIC_KEY,           G_TYPE_STRING, 0, 0 },
	{ NM_SSHTUN_KEY_PRIVATE_KEY,          G_TYPE_STRING, 0, 0 },
	{ NULL,                               G_TYPE_NONE }
};

typedef struct ValidateInfo {
	ValidProperty *table;
	GError **error;
	gboolean have_items;
} ValidateInfo;

static void
validate_one_property (const char *key, const char *value, gpointer user_data)
{
	ValidateInfo *info = (ValidateInfo *) user_data;
	int i;

	if (*(info->error))
		return;

	info->have_items = TRUE;

	/* 'name' is the setting name; always allowed but unused */
	if (!strcmp (key, NM_SETTING_NAME))
		return;

	for (i = 0; info->table[i].name; i++) {
		ValidProperty prop = info->table[i];
		long int tmp;

		if (strcmp (prop.name, key))
			continue;

		switch (prop.type) {
		case G_TYPE_STRING:
			return;
		case G_TYPE_INT:
			errno = 0;
			tmp = strtol (value, NULL, 10);
			if (errno == 0 && tmp >= prop.int_min && tmp <= prop.int_max)
				return; /* valid */

			g_set_error (info->error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             "invalid integer property '%s' or out of range [%d -> %d]",
			             key, prop.int_min, prop.int_max);
			break;
		case G_TYPE_BOOLEAN:
			if (!strcmp (value, "yes") || !strcmp (value, "no"))
				return; /* valid */

			g_set_error (info->error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             "invalid boolean property '%s' (not yes or no)",
			             key);
			break;
		default:
			g_set_error (info->error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             "unhandled property '%s' type %s",
			             key, g_type_name (prop.type));
			break;
		}
	}

	/* Did not find the property from valid_properties or the type did not match */
	if (!info->table[i].name) {
		g_set_error (info->error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		             "property '%s' invalid or not supported",
		             key);
	}
}

static gboolean
nm_sshtun_properties_validate (NMSettingVPN *s_vpn, GError **error)
{
	GError *validate_error = NULL;
	ValidateInfo info = { &valid_properties[0], &validate_error, FALSE };

	nm_setting_vpn_foreach_data_item (s_vpn, validate_one_property, &info);

	if (!info.have_items) {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		             "%s",
		             "No VPN configuration options.");
		return FALSE;
	}

	if (validate_error) {
		*error = validate_error;
		return FALSE;
	}
	return TRUE;
}

static void
sshtun_watch_cb (GPid pid, gint status, gpointer user_data)
{
	NMVPNPlugin *plugin = NM_VPN_PLUGIN (user_data);
	NMSshtunPluginPrivate *priv = NM_SSHTUN_PLUGIN_GET_PRIVATE (plugin);
	NMVPNPluginFailure failure = NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED;
	guint error = 0;
	gboolean good_exit = FALSE;

	if (WIFEXITED (status)) {
		error = WEXITSTATUS (status);
		if (error != 0)
			nm_warning ("sshtun exited with error code %d", error);
    }
	else if (WIFSTOPPED (status))
		nm_warning ("sshtun stopped unexpectedly with signal %d", WSTOPSIG (status));
	else if (WIFSIGNALED (status))
		nm_warning ("sshtun died with signal %d", WTERMSIG (status));
	else
		nm_warning ("sshtun died from an unknown cause");
  
	sshtun_stop (priv->handle);
	sshtun_del (priv->handle);
	priv->handle = NULL;

	switch (error) {
	case 0:
		good_exit = TRUE;
		break;
	default:
		failure = NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED;
		break;
	}

	if (!good_exit)
		nm_vpn_plugin_failure (plugin, failure);

	nm_vpn_plugin_set_state (plugin, NM_VPN_SERVICE_STATE_STOPPED);
}

static GValue *
str_to_gvalue (const char *str, gboolean try_convert)
{
	GValue *val;

	/* Empty */
	if (!str || strlen (str) < 1)
		return NULL;

	if (!g_utf8_validate (str, -1, NULL)) {
		if (try_convert && !(str = g_convert (str, -1, "ISO-8859-1", "UTF-8", NULL, NULL, NULL)))
			str = g_convert (str, -1, "C", "UTF-8", NULL, NULL, NULL);

		if (!str)
			/* Invalid */
			return NULL;
	}

	val = g_slice_new0 (GValue);
	g_value_init (val, G_TYPE_STRING);
	g_value_set_string (val, str);

	return val;
}

static GValue *
uint_to_gvalue (guint32 num)
{
	GValue *val;

	if (num == 0)
		return NULL;

	val = g_slice_new0 (GValue);
	g_value_init (val, G_TYPE_UINT);
	g_value_set_uint (val, num);

	return val;
}

static GValue *
addr_to_gvalue (const char *str)
{
	struct in_addr	temp_addr;

	/* Empty */
	if (!str || strlen (str) < 1)
		return NULL;

	if (inet_pton (AF_INET, str, &temp_addr) <= 0)
		return NULL;

	return uint_to_gvalue (temp_addr.s_addr);
}

static void
helper_failed (DBusGConnection *connection, const char *reason)
{
	DBusGProxy *proxy;
	GError *err = NULL;

	proxy = dbus_g_proxy_new_for_name (connection,
								NM_DBUS_SERVICE_SSHTUN,
								NM_VPN_DBUS_PLUGIN_PATH,
								NM_VPN_DBUS_PLUGIN_INTERFACE);

	dbus_g_proxy_call (proxy, "SetFailure", &err,
				    G_TYPE_STRING, reason,
				    G_TYPE_INVALID,
				    G_TYPE_INVALID);

	if (err) {
		nm_warning ("Could not send failure information: %s", err->message);
		g_error_free (err);
	}

	g_object_unref (proxy);

	exit (1);
}

static void
send_ip4_config (DBusGConnection *connection, GHashTable *config)
{
	DBusGProxy *proxy;
	GError *err = NULL;

	proxy = dbus_g_proxy_new_for_name (connection,
								NM_DBUS_SERVICE_SSHTUN,
								NM_VPN_DBUS_PLUGIN_PATH,
								NM_VPN_DBUS_PLUGIN_INTERFACE);

	dbus_g_proxy_call (proxy, "SetIp4Config", &err,
					   dbus_g_type_get_map ("GHashTable", G_TYPE_STRING, G_TYPE_VALUE),
				    config,
				    G_TYPE_INVALID,
				    G_TYPE_INVALID);

	if (err) {
		nm_warning ("Could not send failure information: %s", err->message);
		g_error_free (err);
	}

	g_object_unref (proxy);
}

static gboolean
nm_sshtun_send_ip4_config (sshtun_handle_t handle)
{
	DBusGConnection *connection;
	GError *err = NULL;
	GHashTable *config;
	GValue *val;
	struct in_addr temp_addr;
	const char *tmp;

	connection = dbus_g_bus_get (DBUS_BUS_SYSTEM, &err);
	if (!connection)
		return FALSE;

	config = g_hash_table_new (g_str_hash, g_str_equal);

	/* Gateway */
	val = addr_to_gvalue (sshtun_get_param (handle, SSHTUN_PARAM_GW_ADDR));
	if (val)
		g_hash_table_insert (config, NM_VPN_PLUGIN_IP4_CONFIG_GATEWAY, val);
	else {
		helper_failed (connection, "VPN Gateway");
		dbus_g_connection_unref (connection);
		return FALSE;
	}

	/* Tunnel device */
	val = str_to_gvalue (sshtun_get_param (handle, SSHTUN_PARAM_TUN_DEV),
						 FALSE);
	if (val)
		g_hash_table_insert (config, NM_VPN_PLUGIN_IP4_CONFIG_TUNDEV, val);
	else {
		helper_failed (connection, "Tunnel Device");
		dbus_g_connection_unref (connection);
		return FALSE;
	}

	/* IP address */
	val = addr_to_gvalue (sshtun_get_param (handle, SSHTUN_PARAM_ADDR));
	if (val)
		g_hash_table_insert (config, NM_VPN_PLUGIN_IP4_CONFIG_ADDRESS, val);
	else {
		helper_failed (connection, "IP4 Address");
		dbus_g_connection_unref (connection);
		return FALSE;
	}

	/* PTP address; for openconnect PTP address == internal IP4 address */
	val = addr_to_gvalue (sshtun_get_param (handle, SSHTUN_PARAM_PEER_ADDR));
	if (val)
		g_hash_table_insert (config, NM_VPN_PLUGIN_IP4_CONFIG_PTP, val);
	else {
		helper_failed (connection, "IP4 PTP Address");
		dbus_g_connection_unref (connection);
		return FALSE;
	}

	/* PTP address; for openconnect PTP address == internal IP4 address */
	val = addr_to_gvalue (sshtun_get_param (handle, SSHTUN_PARAM_PEER_ADDR));
	if (val)
		g_hash_table_insert (config, NM_VPN_PLUGIN_IP4_CONFIG_PTP, val);
	else {
		helper_failed (connection, "IP4 PTP Address");
		dbus_g_connection_unref (connection);
		return FALSE;
	}

	/* Netmask */
	tmp = sshtun_get_param (handle, SSHTUN_PARAM_NETMASK);
	if (tmp && inet_pton (AF_INET, tmp, &temp_addr) > 0) {
		val = uint_to_gvalue (nm_utils_ip4_netmask_to_prefix (temp_addr.s_addr));
		g_hash_table_insert (config, NM_VPN_PLUGIN_IP4_CONFIG_PREFIX, val);
	}

	/* MTU */
	tmp = sshtun_get_param (handle, SSHTUN_PARAM_MTU);
	if (tmp && strlen (tmp)) {
		long int mtu;

		errno = 0;
		mtu = strtol (tmp, NULL, 10);
		if (errno || mtu < 0 || mtu > 20000) {
			nm_warning ("Ignoring invalid tunnel MTU '%s'", tmp);
		} else {
			val = uint_to_gvalue ((guint32) mtu);
			g_hash_table_insert (config, NM_VPN_PLUGIN_IP4_CONFIG_MTU, val);
		}
	}

	send_ip4_config (connection, config);
	dbus_g_connection_unref (connection);

	return TRUE;
}

static gboolean
nm_sshtun_start (NMVPNPlugin *plugin, NMSettingVPN *s_vpn, GError **error)
{
	NMSshtunPluginPrivate *priv = NM_SSHTUN_PLUGIN_GET_PRIVATE(plugin);
	sshtun_handle_t handle;
	const char *tun_mode;
	char *tun_owner = NULL, *host = NULL, *user = NULL,
		*public_key = NULL, *private_key = NULL, *config_script = NULL;
	const char *val;
	int ret;
	gboolean retval = TRUE;
	GSource *sshtun_watch;

	val = nm_setting_vpn_get_user_name (s_vpn);
	if (!val) {
		g_set_error (error,
					 NM_VPN_PLUGIN_ERROR,
					 NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
					 "%s",
					 "Can't get username.");
		retval = FALSE;
		goto out;
	}
	tun_owner = g_strdup (val);

	val = nm_setting_vpn_get_data_item (s_vpn, NM_SSHTUN_KEY_TUN_USE_TAP);
	tun_mode = val && !strcmp (val, "yes") ? "ethernet" : "pointopoint";

	val = nm_setting_vpn_get_data_item (s_vpn, NM_SSHTUN_KEY_USER);
	user = val ? g_strdup (val) : g_strdup (tun_owner);

	val = nm_setting_vpn_get_data_item (s_vpn, NM_SSHTUN_KEY_HOST);
	if (!val) {
		g_set_error (error,
					 NM_VPN_PLUGIN_ERROR,
					 NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
					 "%s",
					 "Host is missing.");
		retval = FALSE;
		goto out;
	}
	host = g_strdup (val);

	val = nm_setting_vpn_get_data_item (s_vpn, NM_SSHTUN_KEY_PUBLIC_KEY);
	if (!val) {
		g_set_error (error,
					 NM_VPN_PLUGIN_ERROR,
					 NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
					 "%s",
					 "SSH public key is missing.");
		retval = FALSE;
		goto out;
	}
	public_key = g_strdup (val);

	val = nm_setting_vpn_get_data_item (s_vpn, NM_SSHTUN_KEY_PRIVATE_KEY);
	if (!val) {
		g_set_error (error,
					 NM_VPN_PLUGIN_ERROR,
					 NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
					 "%s",
					 "SSH private key is missing.");
		retval = FALSE;
		goto out;
	}
	private_key = g_strdup (val);

	val = nm_setting_vpn_get_data_item (s_vpn, NM_SSHTUN_KEY_CONFIG_SCRIPT);
	if (!val) {
		g_set_error (error,
					 NM_VPN_PLUGIN_ERROR,
					 NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
					 "%s",
					 "IP config script is missing.");
		retval = FALSE;
		goto out;
	}
	config_script = g_strdup (val);

	ret = sshtun_new (&handle);
	if (ret < 0) {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_GENERAL,
		             "%s",
		             "Could not allocate memory for an sshtun process.");
		retval = FALSE;
		goto out;
	}

	ret = sshtun_set_params (handle,
							 SSHTUN_PARAM_TUN_MODE, tun_mode,
							 SSHTUN_PARAM_TUN_OWNER, tun_owner,
							 SSHTUN_PARAM_USER, user,
							 SSHTUN_PARAM_HOST, host,
							 SSHTUN_PARAM_SERVICE, "ssh",
							 SSHTUN_PARAM_PUBLIC_KEY, public_key,
							 SSHTUN_PARAM_PRIVATE_KEY, private_key,
							 SSHTUN_PARAM_CONFIG_SCRIPT, config_script,
							 0);
	if (ret < 0) {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		             "%s",
		             "Could not set parameters for an sshtun process.");
		retval = FALSE;
		goto out;
	}

	ret = sshtun_start (handle);
	if (ret < 0) {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_LAUNCH_FAILED,
		             "%s",
		             "Could not start an sshtun process.");
		retval = FALSE;
		goto out;
	}

	priv->handle = handle;
	sshtun_watch = g_child_watch_source_new (sshtun_pid (priv->handle));
	g_source_set_callback (sshtun_watch, (GSourceFunc) sshtun_watch_cb, plugin,
						   NULL);
	g_source_attach (sshtun_watch, NULL);
	g_source_unref (sshtun_watch);

 out:
	g_free (tun_owner);
	g_free (host);
	g_free (user);
	g_free (public_key);
	g_free (private_key);
	g_free (config_script);

	return retval;
}

static gboolean
nm_sshtun_send_ip4_config_timeout (gpointer user_data)
{
	NMVPNPlugin *plugin = (NMVPNPlugin *)user_data;
	NMSshtunPluginPrivate *priv = NM_SSHTUN_PLUGIN_GET_PRIVATE (plugin);

	g_source_remove (priv->send_ip4_config_timeout);
	priv->send_ip4_config_timeout = 0;

	nm_sshtun_send_ip4_config (priv->handle);

	return TRUE;
}

static gboolean
real_connect (NMVPNPlugin   *plugin,
              NMConnection  *connection,
              GError       **error)
{
	NMSettingVPN *s_vpn;
	const char *user_name;
	NMSshtunPluginPrivate *priv = NM_SSHTUN_PLUGIN_GET_PRIVATE (plugin);

	s_vpn = NM_SETTING_VPN (nm_connection_get_setting (connection, NM_TYPE_SETTING_VPN));
	if (!s_vpn) {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_CONNECTION_INVALID,
		             "%s",
		             "Could not process the request because the VPN connection settings were invalid.");
		return FALSE;
	}

	user_name = nm_setting_vpn_get_user_name (s_vpn);
	if (!user_name && !nm_setting_vpn_get_data_item (s_vpn, NM_SSHTUN_KEY_USER)) {
		g_set_error (error,
					 NM_VPN_PLUGIN_ERROR,
					 NM_VPN_PLUGIN_ERROR_CONNECTION_INVALID,
					 "%s",
					 "Could not process the request because no username was provided.");
		return FALSE;
	}

	/* Validate the properties */
	if (!nm_sshtun_properties_validate (s_vpn, error))
		return FALSE;

	/* Finally try to start sshtun */
	if (!nm_sshtun_start (plugin, s_vpn, error))
		return FALSE;

	/* Defer sending IP config until Connect reply is sent */
	priv->send_ip4_config_timeout =
		g_timeout_add_seconds (1, nm_sshtun_send_ip4_config_timeout, plugin);

	return TRUE;
}

static gboolean
real_need_secrets (NMVPNPlugin *plugin,
                   NMConnection *connection,
                   char **setting_name,
                   GError **error)
{
	NMSettingVPN *s_vpn;
	gboolean need_secrets = FALSE;

	g_return_val_if_fail (NM_IS_VPN_PLUGIN (plugin), FALSE);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), FALSE);

	s_vpn = NM_SETTING_VPN (nm_connection_get_setting (connection, NM_TYPE_SETTING_VPN));
	if (!s_vpn) {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_CONNECTION_INVALID,
		             "%s",
		             "Could not process the request because the VPN connection settings were invalid.");
		return FALSE;
	}

#if 0
	if (!nm_setting_vpn_get_secret (s_vpn, NM_SSHTUN_KEY_PASSWORD))
		need_secrets = TRUE;
#endif

	if (need_secrets)
		*setting_name = NM_SETTING_VPN_SETTING_NAME;

	return need_secrets;
}

static gboolean
real_disconnect (NMVPNPlugin	 *plugin,
				 GError		**err)
{
	NMSshtunPluginPrivate *priv = NM_SSHTUN_PLUGIN_GET_PRIVATE (plugin);

	sshtun_stop (priv->handle);
	sshtun_del (priv->handle);
	priv->handle = NULL;

	return TRUE;
}

static void
nm_sshtun_plugin_init (NMSshtunPlugin *plugin)
{
}

static void
nm_sshtun_plugin_class_init (NMSshtunPluginClass *plugin_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (plugin_class);
	NMVPNPluginClass *parent_class = NM_VPN_PLUGIN_CLASS (plugin_class);

	g_type_class_add_private (object_class, sizeof (NMSshtunPluginPrivate));

	/* virtual methods */
	parent_class->connect      = real_connect;
	parent_class->need_secrets = real_need_secrets;
	parent_class->disconnect   = real_disconnect;
}

static void
plugin_state_changed (NMSshtunPlugin *plugin,
                      NMVPNServiceState state,
                      gpointer user_data)
{
}

NMSshtunPlugin *
nm_sshtun_plugin_new (void)
{
	NMSshtunPlugin *plugin;

	plugin = (NMSshtunPlugin *) g_object_new (NM_TYPE_SSHTUN_PLUGIN,
											  NM_VPN_PLUGIN_DBUS_SERVICE_NAME,
											  NM_DBUS_SERVICE_SSHTUN,
											  NULL);
	if (plugin)
		g_signal_connect (G_OBJECT (plugin), "state-changed", G_CALLBACK (plugin_state_changed), NULL);
		
	return plugin;
}

static void
quit_mainloop (NMVPNPlugin *plugin, gpointer user_data)
{
	g_main_loop_quit ((GMainLoop *) user_data);
}

int
main (int argc, char *argv[])
{
	NMSshtunPlugin *plugin;
	GMainLoop *main_loop;

	g_type_init ();

	if (system ("/sbin/modprobe tun") == -1)
		exit (EXIT_FAILURE);

	plugin = nm_sshtun_plugin_new ();
	if (!plugin)
		exit (EXIT_FAILURE);

	main_loop = g_main_loop_new (NULL, FALSE);
	g_signal_connect (plugin, "quit",
				   G_CALLBACK (quit_mainloop),
				   main_loop);

	g_main_loop_run (main_loop);

	g_main_loop_unref (main_loop);
	g_object_unref (plugin);

	exit (EXIT_SUCCESS);
}
