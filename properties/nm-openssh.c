/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/***************************************************************************
 *
 * nm-openssh.c : GNOME UI dialogs for configuring OpenSSH VPN connections
 *
 * Copyright (C) 2005 Tim Niemueller <tim@niemueller.de>
 * Copyright (C) 2008 Dan Williams, <dcbw@redhat.com>
 * Based on work by David Zeuthen, <davidz@redhat.com>
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
 **************************************************************************/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <glib/gi18n-lib.h>
#include <gnome-keyring-memory.h>
#include <string.h>
#include <gtk/gtk.h>
#include <glade/glade.h>

#define NM_VPN_API_SUBJECT_TO_CHANGE

#include <nm-vpn-plugin-ui-interface.h>
#include <nm-setting-vpn.h>
#include <nm-setting-connection.h>
#include <nm-setting-ip4-config.h>

#include "common-gnome/keyring-helpers.h"
#include "src/nm-openssh-service.h"
#include "nm-openssh.h"

#define OPENSSH_PLUGIN_NAME    _("OpenSSH pseudo VPN")
#define OPENSSH_PLUGIN_DESC    _("Compatible with the OpenSSH server.")
#define OPENSSH_PLUGIN_SERVICE NM_DBUS_SERVICE_OPENSSH 


/************** plugin class **************/

static void openssh_plugin_ui_interface_init (NMVpnPluginUiInterface *iface_class);

G_DEFINE_TYPE_EXTENDED (OpensshPluginUi, openssh_plugin_ui, G_TYPE_OBJECT, 0,
						G_IMPLEMENT_INTERFACE (NM_TYPE_VPN_PLUGIN_UI_INTERFACE,
											   openssh_plugin_ui_interface_init))

/************** UI widget class **************/

static void openssh_plugin_ui_widget_interface_init (NMVpnPluginUiWidgetInterface *iface_class);

G_DEFINE_TYPE_EXTENDED (OpensshPluginUiWidget, openssh_plugin_ui_widget, G_TYPE_OBJECT, 0,
						G_IMPLEMENT_INTERFACE (NM_TYPE_VPN_PLUGIN_UI_WIDGET_INTERFACE,
											   openssh_plugin_ui_widget_interface_init))

#define OPENSSH_PLUGIN_UI_WIDGET_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), OPENSSH_TYPE_PLUGIN_UI_WIDGET, OpensshPluginUiWidgetPrivate))

typedef struct {
	GladeXML *xml;
	GtkWidget *widget;
	GtkSizeGroup *group;
	GtkWindowGroup *window_group;
	gboolean window_added;
} OpensshPluginUiWidgetPrivate;


#define COL_TUN_MODE_NAME 0
#define COL_TUN_MODE 1

GQuark
openssh_plugin_ui_error_quark (void)
{
	static GQuark error_quark = 0;

	if (G_UNLIKELY (error_quark == 0))
		error_quark = g_quark_from_static_string ("openssh-plugin-ui-error-quark");

	return error_quark;
}

/* This should really be standard. */
#define ENUM_ENTRY(NAME, DESC) { NAME, "" #NAME "", DESC }

GType
openssh_plugin_ui_error_get_type (void)
{
	static GType etype = 0;

	if (etype == 0) {
		static const GEnumValue values[] = {
			/* Unknown error. */
			ENUM_ENTRY (OPENSSH_PLUGIN_UI_ERROR_UNKNOWN, "UnknownError"),
			/* The connection was missing invalid. */
			ENUM_ENTRY (OPENSSH_PLUGIN_UI_ERROR_INVALID_CONNECTION, "InvalidConnection"),
			/* The specified property was invalid. */
			ENUM_ENTRY (OPENSSH_PLUGIN_UI_ERROR_INVALID_PROPERTY, "InvalidProperty"),
			/* The specified property was missing and is required. */
			ENUM_ENTRY (OPENSSH_PLUGIN_UI_ERROR_MISSING_PROPERTY, "MissingProperty"),
			/* The file to import could not be read. */
			ENUM_ENTRY (OPENSSH_PLUGIN_UI_ERROR_FILE_NOT_READABLE, "FileNotReadable"),
			{ 0, 0, 0 }
		};
		etype = g_enum_register_static ("OpensshPluginUiError", values);
	}
	return etype;
}

static gboolean
check_validity (OpensshPluginUiWidget *self, GError **error)
{
	OpensshPluginUiWidgetPrivate *priv = OPENSSH_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
	GtkWidget *widget;
	const char *str;

	widget = glade_xml_get_widget (priv->xml, "gateway_entry");
	str = gtk_entry_get_text (GTK_ENTRY (widget));
	if (!str || !strlen (str)) {
		g_set_error (error,
		             OPENSSH_PLUGIN_UI_ERROR,
		             OPENSSH_PLUGIN_UI_ERROR_INVALID_PROPERTY,
		             NM_OPENSSH_KEY_HOST);
		return FALSE;
	}
	widget = glade_xml_get_widget (priv->xml, "config_script_entry");
	str = gtk_entry_get_text (GTK_ENTRY (widget));
	if (!str || !strlen (str)) {
		g_set_error (error,
		             OPENSSH_PLUGIN_UI_ERROR,
		             OPENSSH_PLUGIN_UI_ERROR_INVALID_PROPERTY,
		             NM_OPENSSH_KEY_CONFIG_SCRIPT);
		return FALSE;
	}
	widget = glade_xml_get_widget (priv->xml, "public_key_chooser");
	str = gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (widget));
	if (!str || !strlen (str)) {
		g_set_error (error,
		             OPENSSH_PLUGIN_UI_ERROR,
		             OPENSSH_PLUGIN_UI_ERROR_INVALID_PROPERTY,
		             NM_OPENSSH_KEY_PUBLIC_KEY);
		return FALSE;
	}
	widget = glade_xml_get_widget (priv->xml, "private_key_chooser");
	str = gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (widget));
	if (!str || !strlen (str)) {
		g_set_error (error,
		             OPENSSH_PLUGIN_UI_ERROR,
		             OPENSSH_PLUGIN_UI_ERROR_INVALID_PROPERTY,
		             NM_OPENSSH_KEY_PRIVATE_KEY);
		return FALSE;
	}

	return TRUE;
}

static void
show_password_cb (GtkToggleButton *togglebutton, GtkEntry *password_entry)
{
	gtk_entry_set_visibility (password_entry, gtk_toggle_button_get_active (togglebutton));
}

static void
fill_password (GtkWidget *widget,
			   NMConnection *connection)
{
	char *password = NULL;

	if (nm_connection_get_scope (connection) == NM_CONNECTION_SCOPE_SYSTEM) {
		NMSettingVPN *s_vpn;

		s_vpn = (NMSettingVPN *) nm_connection_get_setting (connection, NM_TYPE_SETTING_VPN);
		if (s_vpn) {
			const char *tmp;

			tmp = nm_setting_vpn_get_secret (s_vpn, NM_OPENSSH_KEY_PASSWORD);
			if (tmp)
				password = gnome_keyring_memory_strdup (tmp);
		}
	} else {
		NMSettingConnection *s_con;
		gboolean unused;

		s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
		password = keyring_helpers_lookup_secret (nm_setting_connection_get_uuid (s_con),
		                                          NM_OPENSSH_KEY_PASSWORD,
		                                          &unused);
	}

	if (password) {
		gtk_entry_set_text (GTK_ENTRY (widget), password);
		gnome_keyring_memory_free (password);
	}
}

static void
stuff_changed_cb (GtkWidget *widget, gpointer user_data)
{
	g_signal_emit_by_name (OPENSSH_PLUGIN_UI_WIDGET (user_data), "changed");
}

static void public_key_selection_changed_cb (GtkWidget *, gpointer);
static void private_key_selection_changed_cb (GtkWidget *, gpointer);

static void
public_key_selection_changed_cb (GtkWidget *widget, gpointer user_data)
{
	OpensshPluginUiWidget *self = OPENSSH_PLUGIN_UI_WIDGET (user_data);
	OpensshPluginUiWidgetPrivate *priv = OPENSSH_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
	GtkWidget *private_key_chooser;
	const char *public_key;
	char *private_key;

	public_key = gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (widget));
	if (!public_key || !strlen (public_key)) {
		stuff_changed_cb (widget, user_data);
		return;
	}

	/* Construct the private key filename from the public key filename. */
	private_key_chooser = glade_xml_get_widget (priv->xml, "private_key_chooser");
	private_key = gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (private_key_chooser));
	if (!private_key || !strlen (private_key)) {
		char *p;

		private_key = g_strdup (public_key);
		p = strrchr (private_key, '.');
		if (p && !strcmp (p, ".pub")) {
			*p = '\0';
			if (g_file_test (private_key, G_FILE_TEST_EXISTS)) {
				g_signal_handlers_disconnect_matched (G_OBJECT (private_key_chooser),
													  G_SIGNAL_MATCH_FUNC,
													  0, 0, NULL,
													  G_CALLBACK (private_key_selection_changed_cb),
													  user_data);
				gtk_file_chooser_set_filename (GTK_FILE_CHOOSER (private_key_chooser), private_key);
				g_signal_connect (G_OBJECT (private_key_chooser),
								  "selection-changed",
								  G_CALLBACK (private_key_selection_changed_cb),
								  user_data);
			}
		}
		g_free (private_key);
	}
	stuff_changed_cb (widget, user_data);
}

static void
private_key_selection_changed_cb (GtkWidget *widget, gpointer user_data)
{
	OpensshPluginUiWidget *self = OPENSSH_PLUGIN_UI_WIDGET (user_data);
	OpensshPluginUiWidgetPrivate *priv = OPENSSH_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
	GtkWidget *public_key_chooser;
	const char *private_key;
	char *public_key;

	private_key = gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (widget));
	if (!private_key || !strlen (private_key)) {
		stuff_changed_cb (widget, user_data);
		return;
	}

	/* Construct the public key filename from the private key filename. */
	public_key_chooser = glade_xml_get_widget (priv->xml, "public_key_chooser");
	public_key = gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (public_key_chooser));
	if (!public_key || !strlen (public_key)) {
		public_key = g_malloc0 (strlen (private_key) + 5);
		strcpy (public_key, private_key);
		strcat (public_key, ".pub");
		if (g_file_test (public_key, G_FILE_TEST_EXISTS)) {
			g_signal_handlers_disconnect_matched (G_OBJECT (public_key_chooser),
												  G_SIGNAL_MATCH_FUNC,
												  0, 0, NULL,
												  G_CALLBACK (public_key_selection_changed_cb),
												  user_data);
			gtk_file_chooser_set_filename (GTK_FILE_CHOOSER (public_key_chooser), public_key);
			g_signal_connect (G_OBJECT (public_key_chooser),
							  "selection-changed",
							  G_CALLBACK (public_key_selection_changed_cb),
							  user_data);
		}
		g_free (public_key);
	}
	stuff_changed_cb (widget, user_data);
}

static gboolean
not_public_key_filter (const GtkFileFilterInfo *filter_info, gpointer data)
{
	char *p;

	if (!filter_info->filename)
		return FALSE;

	p = strrchr (filter_info->filename, '.');
	if (p && !strcasecmp (p, ".pub"))
		return FALSE;
	return TRUE;
}

static gboolean
init_plugin_ui (OpensshPluginUiWidget *self, NMConnection *connection, GError **error)
{
	OpensshPluginUiWidgetPrivate *priv = OPENSSH_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
	NMSettingVPN *s_vpn;
	GtkWidget *widget;
	GtkWidget *show_password;
	GtkListStore *store;
	GtkTreeIter iter;
	GtkFileFilter *filter;
	int active = -1;
	gboolean is_tap = FALSE;
	const char *value;

	s_vpn = (NMSettingVPN *) nm_connection_get_setting (connection, NM_TYPE_SETTING_VPN);

	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENSSH_KEY_TUN_USE_TAP);
		if (value && !strcmp (value, "yes"))
			is_tap = TRUE;
	}

	priv->group = gtk_size_group_new (GTK_SIZE_GROUP_HORIZONTAL);

	widget = glade_xml_get_widget (priv->xml, "gateway_entry");
	if (!widget)
		return FALSE;
	gtk_size_group_add_widget (priv->group, widget);
	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENSSH_KEY_HOST);
		if (value)
			gtk_entry_set_text (GTK_ENTRY (widget), value);
	}
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);

	widget = glade_xml_get_widget (priv->xml, "tun_mode_combo");
	if (!widget)
		return FALSE;
	gtk_size_group_add_widget (priv->group, widget);

	store = gtk_list_store_new (2, G_TYPE_STRING, G_TYPE_INT);
	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter,
	                    COL_TUN_MODE_NAME, _("Point-to-Point (TUN)"),
	                    COL_TUN_MODE, NM_OPENSSH_TUN_MODE_TUN,
	                    -1);
	if (active == -1 && !is_tap)
		active = 0;
	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter,
	                    COL_TUN_MODE_NAME, _("Ethernet (TAP)"),
	                    COL_TUN_MODE, NM_OPENSSH_TUN_MODE_TAP,
	                    -1);
	if (active == -1 && is_tap)
		active = 1;
	gtk_combo_box_set_model (GTK_COMBO_BOX (widget), GTK_TREE_MODEL (store));
	g_object_unref (store);
	g_signal_connect (widget, "changed", G_CALLBACK (stuff_changed_cb),
					  self);
	gtk_combo_box_set_active (GTK_COMBO_BOX (widget), active < 0 ? 0 : active);

	widget = glade_xml_get_widget (priv->xml, "config_script_entry");
	if (!widget)
		return FALSE;
	gtk_size_group_add_widget (priv->group, widget);
	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENSSH_KEY_CONFIG_SCRIPT);
		if (value)
			gtk_entry_set_text (GTK_ENTRY (widget), value);
	}

	widget = glade_xml_get_widget (priv->xml, "user_entry");
	if (!widget)
		return FALSE;
	gtk_size_group_add_widget (priv->group, widget);
	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENSSH_KEY_USER);
		if (value)
			gtk_entry_set_text (GTK_ENTRY (widget), value);
	}
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);

	widget = glade_xml_get_widget (priv->xml, "public_key_chooser");
	if (!widget)
		return FALSE;
	gtk_size_group_add_widget (priv->group, widget);
	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENSSH_KEY_PUBLIC_KEY);
		if (value)
			gtk_file_chooser_set_filename (GTK_FILE_CHOOSER (widget), value);
	}
	filter = gtk_file_filter_new ();
	gtk_file_filter_set_name (GTK_FILE_FILTER (filter),
							  _("SSH public key (*.pub)"));
	gtk_file_filter_add_pattern (GTK_FILE_FILTER (filter), "*.pub");
	gtk_file_chooser_add_filter (GTK_FILE_CHOOSER (widget),
								 GTK_FILE_FILTER (filter));
	filter = gtk_file_filter_new ();
	gtk_file_filter_set_name (GTK_FILE_FILTER (filter),
							  _("All files"));
	gtk_file_filter_add_pattern (GTK_FILE_FILTER (filter), "*");
	gtk_file_chooser_add_filter (GTK_FILE_CHOOSER (widget),
								 GTK_FILE_FILTER (filter));
	gtk_file_chooser_set_local_only (GTK_FILE_CHOOSER (widget), TRUE);
	gtk_file_chooser_button_set_title (GTK_FILE_CHOOSER_BUTTON (widget),
	                                   _("Choose an SSH public key..."));
	g_signal_connect (G_OBJECT (widget), "selection-changed",
					  G_CALLBACK (public_key_selection_changed_cb), self);

	widget = glade_xml_get_widget (priv->xml, "private_key_chooser");
	if (!widget)
		return FALSE;
	gtk_size_group_add_widget (priv->group, widget);
	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENSSH_KEY_PRIVATE_KEY);
		if (value)
			gtk_file_chooser_set_filename (GTK_FILE_CHOOSER (widget), value);
	}
	filter = gtk_file_filter_new ();
	gtk_file_filter_set_name (GTK_FILE_FILTER (filter),
							  _("SSH private key"));
	gtk_file_filter_add_custom (GTK_FILE_FILTER (filter),
								GTK_FILE_FILTER_FILENAME,
								not_public_key_filter, NULL, NULL);
	gtk_file_chooser_add_filter (GTK_FILE_CHOOSER (widget),
								 GTK_FILE_FILTER (filter));
	filter = gtk_file_filter_new ();
	gtk_file_filter_set_name (GTK_FILE_FILTER (filter),
							  _("All files"));
	gtk_file_filter_add_pattern (GTK_FILE_FILTER (filter), "*");
	gtk_file_chooser_add_filter (GTK_FILE_CHOOSER (widget),
								 GTK_FILE_FILTER (filter));
	gtk_file_chooser_set_local_only (GTK_FILE_CHOOSER (widget), TRUE);
	gtk_file_chooser_button_set_title (GTK_FILE_CHOOSER_BUTTON (widget),
	                                   _("Choose an SSH private key..."));
	g_signal_connect (G_OBJECT (widget), "selection-changed",
					  G_CALLBACK (private_key_selection_changed_cb), self);

	widget = glade_xml_get_widget (priv->xml, "password_entry");
	if (!widget)
		return FALSE;
	gtk_size_group_add_widget (priv->group, widget);
	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_OPENSSH_KEY_PASSWORD);
		if (value)
			gtk_entry_set_text (GTK_ENTRY (widget), value);
	}
	fill_password (widget, connection);
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);

	show_password = glade_xml_get_widget (priv->xml, "show_password");
	if (!show_password)
		return FALSE;
	g_signal_connect (show_password, "toggled", G_CALLBACK (show_password_cb), widget);

	return TRUE;
}

static GObject *
get_widget (NMVpnPluginUiWidgetInterface *iface)
{
	OpensshPluginUiWidget *self = OPENSSH_PLUGIN_UI_WIDGET (iface);
	OpensshPluginUiWidgetPrivate *priv = OPENSSH_PLUGIN_UI_WIDGET_GET_PRIVATE (self);

	return G_OBJECT (priv->widget);
}

static gboolean
update_connection (NMVpnPluginUiWidgetInterface *iface,
                   NMConnection *connection,
                   GError **error)
{
	OpensshPluginUiWidget *self = OPENSSH_PLUGIN_UI_WIDGET (iface);
	OpensshPluginUiWidgetPrivate *priv = OPENSSH_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
	NMSettingVPN *s_vpn;
	GtkWidget *widget;
	GtkTreeModel *model;
	GtkTreeIter iter;
	char *str;
	gboolean valid = FALSE;
	gint tun_mode = 0;

	if (!check_validity (self, error))
		return FALSE;

	s_vpn = NM_SETTING_VPN (nm_setting_vpn_new ());
	g_object_set (s_vpn, NM_SETTING_VPN_SERVICE_TYPE, NM_DBUS_SERVICE_OPENSSH, NULL);

	/* Gateway */
	widget = glade_xml_get_widget (priv->xml, "gateway_entry");
	str = (char *) gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && strlen (str))
		nm_setting_vpn_add_data_item (s_vpn, NM_OPENSSH_KEY_HOST, str);

	/* Tunnel mode */
	widget = glade_xml_get_widget (priv->xml, "tun_mode_combo");
	model = gtk_combo_box_get_model (GTK_COMBO_BOX (widget));
	g_assert (model);
	g_assert (gtk_combo_box_get_active_iter (GTK_COMBO_BOX (widget), &iter));

	gtk_tree_model_get (model, &iter, COL_TUN_MODE, &tun_mode, -1);
	nm_setting_vpn_add_data_item (s_vpn, NM_OPENSSH_KEY_TUN_USE_TAP,
								  tun_mode == NM_OPENSSH_TUN_MODE_TAP
								  ? "yes" : "no");

	/* Config script */
	widget = glade_xml_get_widget (priv->xml, "config_script_entry");
	str = (char *) gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && strlen (str))
		nm_setting_vpn_add_data_item (s_vpn, NM_OPENSSH_KEY_CONFIG_SCRIPT, str);

	/* SSH user */
	widget = glade_xml_get_widget (priv->xml, "user_entry");
	str = (char *) gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && strlen (str))
		nm_setting_vpn_add_data_item (s_vpn, NM_OPENSSH_KEY_USER, str);

	/* SSH public key */
	widget = glade_xml_get_widget (priv->xml, "public_key_chooser");
	str = (char *) gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (widget));
	if (str && strlen (str))
		nm_setting_vpn_add_data_item (s_vpn, NM_OPENSSH_KEY_PUBLIC_KEY, str);

	/* SSH private key */
	widget = glade_xml_get_widget (priv->xml, "private_key_chooser");
	str = (char *) gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (widget));
	if (str && strlen (str))
		nm_setting_vpn_add_data_item (s_vpn, NM_OPENSSH_KEY_PRIVATE_KEY, str);

	nm_connection_add_setting (connection, NM_SETTING (s_vpn));
	valid = TRUE;

	return valid;
}

static gboolean
save_secrets (NMVpnPluginUiWidgetInterface *iface,
              NMConnection *connection,
              GError **error)
{
	OpensshPluginUiWidgetPrivate *priv = OPENSSH_PLUGIN_UI_WIDGET_GET_PRIVATE (iface);
	NMSettingConnection *s_con;
	GtkWidget *w;
	const char *secret;
	GnomeKeyringResult result;
	const char *uuid, *id;
	gboolean ret = FALSE;

	s_con = (NMSettingConnection *) nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION);
	if (!s_con) {
		g_set_error (error,
					 OPENSSH_PLUGIN_UI_ERROR,
		             OPENSSH_PLUGIN_UI_ERROR_INVALID_CONNECTION,
		             "%s", "missing 'connection' setting");
		return FALSE;
	}

	id = nm_setting_connection_get_id (s_con);
	uuid = nm_setting_connection_get_uuid (s_con);

	w = glade_xml_get_widget (priv->xml, "password_entry");
	g_assert (w);
	secret = gtk_entry_get_text (GTK_ENTRY (w));
	if (secret && strlen (secret)) {
		result = keyring_helpers_save_secret (uuid, id, NULL, NM_OPENSSH_KEY_PASSWORD, secret);
		ret = result == GNOME_KEYRING_RESULT_OK;
		if (!ret)
			g_warning ("%s: failed to save user password to keyring.", __func__);
	} else
		ret = keyring_helpers_delete_secret (uuid, NM_OPENSSH_KEY_PASSWORD);

	if (!ret)
		g_set_error (error, OPENSSH_PLUGIN_UI_ERROR,
					 OPENSSH_PLUGIN_UI_ERROR_UNKNOWN,
					 "%s", "Saving secrets to gnome keyring failed.");
	return ret;
}

static NMVpnPluginUiWidgetInterface *
nm_vpn_plugin_ui_widget_interface_new (NMConnection *connection, GError **error)
{
	NMVpnPluginUiWidgetInterface *object;
	OpensshPluginUiWidgetPrivate *priv;
	char *glade_file;

	if (error)
		g_return_val_if_fail (*error == NULL, NULL);

	object = NM_VPN_PLUGIN_UI_WIDGET_INTERFACE (g_object_new (OPENSSH_TYPE_PLUGIN_UI_WIDGET, NULL));
	if (!object) {
		g_set_error (error, OPENSSH_PLUGIN_UI_ERROR, 0, "could not create openssh object");
		return NULL;
	}

	priv = OPENSSH_PLUGIN_UI_WIDGET_GET_PRIVATE (object);

	glade_file = g_strdup_printf ("%s/%s", GLADEDIR, "nm-openssh-dialog.glade");
	priv->xml = glade_xml_new (glade_file, "openssh-vbox", GETTEXT_PACKAGE);
	if (priv->xml == NULL) {
		g_set_error (error, OPENSSH_PLUGIN_UI_ERROR, 0,
		             "could not load required resources at %s", glade_file);
		g_free (glade_file);
		g_object_unref (object);
		return NULL;
	}
	g_free (glade_file);

	priv->widget = glade_xml_get_widget (priv->xml, "openssh-vbox");
	if (!priv->widget) {
		g_set_error (error, OPENSSH_PLUGIN_UI_ERROR, 0, "could not load UI widget");
		g_object_unref (object);
		return NULL;
	}
	g_object_ref_sink (priv->widget);

	priv->window_group = gtk_window_group_new ();

	if (!init_plugin_ui (OPENSSH_PLUGIN_UI_WIDGET (object), connection, error)) {
		g_object_unref (object);
		return NULL;
	}

	return object;
}

static void
dispose (GObject *object)
{
	OpensshPluginUiWidget *plugin = OPENSSH_PLUGIN_UI_WIDGET (object);
	OpensshPluginUiWidgetPrivate *priv = OPENSSH_PLUGIN_UI_WIDGET_GET_PRIVATE (plugin);

	if (priv->group)
		g_object_unref (priv->group);

	if (priv->window_group)
		g_object_unref (priv->window_group);

	if (priv->widget)
		g_object_unref (priv->widget);

	if (priv->xml)
		g_object_unref (priv->xml);

	G_OBJECT_CLASS (openssh_plugin_ui_widget_parent_class)->dispose (object);
}

static void
openssh_plugin_ui_widget_class_init (OpensshPluginUiWidgetClass *req_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (req_class);

	g_type_class_add_private (req_class, sizeof (OpensshPluginUiWidgetPrivate));

	object_class->dispose = dispose;
}

static void
openssh_plugin_ui_widget_init (OpensshPluginUiWidget *plugin)
{
}

static void
openssh_plugin_ui_widget_interface_init (NMVpnPluginUiWidgetInterface *iface_class)
{
	/* interface implementation */
	iface_class->get_widget = get_widget;
	iface_class->update_connection = update_connection;
	iface_class->save_secrets = save_secrets;
}

static guint32
get_capabilities (NMVpnPluginUiInterface *iface)
{
	return 0;
}

static gboolean
delete_connection (NMVpnPluginUiInterface *iface,
                   NMConnection *connection,
                   GError **error)
{
	return TRUE;
}

static NMVpnPluginUiWidgetInterface *
ui_factory (NMVpnPluginUiInterface *iface, NMConnection *connection, GError **error)
{
	return nm_vpn_plugin_ui_widget_interface_new (connection, error);
}

static void
get_property (GObject *object, guint prop_id,
			  GValue *value, GParamSpec *pspec)
{
	switch (prop_id) {
	case NM_VPN_PLUGIN_UI_INTERFACE_PROP_NAME:
		g_value_set_string (value, OPENSSH_PLUGIN_NAME);
		break;
	case NM_VPN_PLUGIN_UI_INTERFACE_PROP_DESC:
		g_value_set_string (value, OPENSSH_PLUGIN_DESC);
		break;
	case NM_VPN_PLUGIN_UI_INTERFACE_PROP_SERVICE:
		g_value_set_string (value, OPENSSH_PLUGIN_SERVICE);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
openssh_plugin_ui_class_init (OpensshPluginUiClass *req_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (req_class);

	object_class->get_property = get_property;

	g_object_class_override_property (object_class,
									  NM_VPN_PLUGIN_UI_INTERFACE_PROP_NAME,
									  NM_VPN_PLUGIN_UI_INTERFACE_NAME);

	g_object_class_override_property (object_class,
									  NM_VPN_PLUGIN_UI_INTERFACE_PROP_DESC,
									  NM_VPN_PLUGIN_UI_INTERFACE_DESC);

	g_object_class_override_property (object_class,
									  NM_VPN_PLUGIN_UI_INTERFACE_PROP_SERVICE,
									  NM_VPN_PLUGIN_UI_INTERFACE_SERVICE);
}

static void
openssh_plugin_ui_init (OpensshPluginUi *plugin)
{
}

static void
openssh_plugin_ui_interface_init (NMVpnPluginUiInterface *iface_class)
{
	/* interface implementation */
	iface_class->ui_factory = ui_factory;
	iface_class->get_capabilities = get_capabilities;
	iface_class->delete_connection = delete_connection;
}


G_MODULE_EXPORT NMVpnPluginUiInterface *
nm_vpn_plugin_ui_factory (GError **error)
{
	if (error)
		g_return_val_if_fail (*error == NULL, NULL);

	return NM_VPN_PLUGIN_UI_INTERFACE (g_object_new (OPENSSH_TYPE_PLUGIN_UI, NULL));
}

