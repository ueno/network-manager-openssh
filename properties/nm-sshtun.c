/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/***************************************************************************
 *
 * nm-sshtun.c : GNOME UI dialogs for configuring sshtun VPN connections
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
#include <string.h>
#include <gtk/gtk.h>
#include <glade/glade.h>

#define NM_VPN_API_SUBJECT_TO_CHANGE

#include <nm-vpn-plugin-ui-interface.h>
#include <nm-setting-vpn.h>
#include <nm-setting-connection.h>
#include <nm-setting-ip4-config.h>

#include "src/nm-sshtun-service.h"
#include "nm-sshtun.h"

#define SSHTUN_PLUGIN_NAME    _("Tunnel over SSH (sshtun)")
#define SSHTUN_PLUGIN_DESC    _("Compatible with the OpenSSH server.")
#define SSHTUN_PLUGIN_SERVICE NM_DBUS_SERVICE_SSHTUN 


/************** plugin class **************/

static void sshtun_plugin_ui_interface_init (NMVpnPluginUiInterface *iface_class);

G_DEFINE_TYPE_EXTENDED (SshtunPluginUi, sshtun_plugin_ui, G_TYPE_OBJECT, 0,
						G_IMPLEMENT_INTERFACE (NM_TYPE_VPN_PLUGIN_UI_INTERFACE,
											   sshtun_plugin_ui_interface_init))

/************** UI widget class **************/

static void sshtun_plugin_ui_widget_interface_init (NMVpnPluginUiWidgetInterface *iface_class);

G_DEFINE_TYPE_EXTENDED (SshtunPluginUiWidget, sshtun_plugin_ui_widget, G_TYPE_OBJECT, 0,
						G_IMPLEMENT_INTERFACE (NM_TYPE_VPN_PLUGIN_UI_WIDGET_INTERFACE,
											   sshtun_plugin_ui_widget_interface_init))

#define SSHTUN_PLUGIN_UI_WIDGET_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), SSHTUN_TYPE_PLUGIN_UI_WIDGET, SshtunPluginUiWidgetPrivate))

typedef struct {
	GladeXML *xml;
	GtkWidget *widget;
	GtkSizeGroup *group;
	GtkWindowGroup *window_group;
	gboolean window_added;
} SshtunPluginUiWidgetPrivate;


#define COL_TUN_MODE_NAME 0
#define COL_TUN_MODE 1

GQuark
sshtun_plugin_ui_error_quark (void)
{
	static GQuark error_quark = 0;

	if (G_UNLIKELY (error_quark == 0))
		error_quark = g_quark_from_static_string ("sshtun-plugin-ui-error-quark");

	return error_quark;
}

/* This should really be standard. */
#define ENUM_ENTRY(NAME, DESC) { NAME, "" #NAME "", DESC }

GType
sshtun_plugin_ui_error_get_type (void)
{
	static GType etype = 0;

	if (etype == 0) {
		static const GEnumValue values[] = {
			/* Unknown error. */
			ENUM_ENTRY (SSHTUN_PLUGIN_UI_ERROR_UNKNOWN, "UnknownError"),
			/* The connection was missing invalid. */
			ENUM_ENTRY (SSHTUN_PLUGIN_UI_ERROR_INVALID_CONNECTION, "InvalidConnection"),
			/* The specified property was invalid. */
			ENUM_ENTRY (SSHTUN_PLUGIN_UI_ERROR_INVALID_PROPERTY, "InvalidProperty"),
			/* The specified property was missing and is required. */
			ENUM_ENTRY (SSHTUN_PLUGIN_UI_ERROR_MISSING_PROPERTY, "MissingProperty"),
			/* The file to import could not be read. */
			ENUM_ENTRY (SSHTUN_PLUGIN_UI_ERROR_FILE_NOT_READABLE, "FileNotReadable"),
			{ 0, 0, 0 }
		};
		etype = g_enum_register_static ("SshtunPluginUiError", values);
	}
	return etype;
}

static gboolean
check_validity (SshtunPluginUiWidget *self, GError **error)
{
	SshtunPluginUiWidgetPrivate *priv = SSHTUN_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
	GtkWidget *widget;
	const char *str;

	widget = glade_xml_get_widget (priv->xml, "gateway_entry");
	str = gtk_entry_get_text (GTK_ENTRY (widget));
	if (!str || !strlen (str)) {
		g_set_error (error,
		             SSHTUN_PLUGIN_UI_ERROR,
		             SSHTUN_PLUGIN_UI_ERROR_INVALID_PROPERTY,
		             NM_SSHTUN_KEY_HOST);
		return FALSE;
	}
	widget = glade_xml_get_widget (priv->xml, "user_entry");
	str = gtk_entry_get_text (GTK_ENTRY (widget));
	if (!str || !strlen (str)) {
		g_set_error (error,
		             SSHTUN_PLUGIN_UI_ERROR,
		             SSHTUN_PLUGIN_UI_ERROR_INVALID_PROPERTY,
		             NM_SSHTUN_KEY_USER);
		return FALSE;
	}
	widget = glade_xml_get_widget (priv->xml, "config_script");
	str = gtk_entry_get_text (GTK_ENTRY (widget));
	if (!str || !strlen (str)) {
		g_set_error (error,
		             SSHTUN_PLUGIN_UI_ERROR,
		             SSHTUN_PLUGIN_UI_ERROR_INVALID_PROPERTY,
		             NM_SSHTUN_KEY_CONFIG_SCRIPT);
		return FALSE;
	}
	widget = glade_xml_get_widget (priv->xml, "public_key_chooser");
	str = gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (widget));
	if (!str || !strlen (str)) {
		g_set_error (error,
		             SSHTUN_PLUGIN_UI_ERROR,
		             SSHTUN_PLUGIN_UI_ERROR_INVALID_PROPERTY,
		             NM_SSHTUN_KEY_PUBLIC_KEY);
		return FALSE;
	}
	widget = glade_xml_get_widget (priv->xml, "private_key_chooser");
	str = gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (widget));
	if (!str || !strlen (str)) {
		g_set_error (error,
		             SSHTUN_PLUGIN_UI_ERROR,
		             SSHTUN_PLUGIN_UI_ERROR_INVALID_PROPERTY,
		             NM_SSHTUN_KEY_PRIVATE_KEY);
		return FALSE;
	}

	return TRUE;
}

static void
stuff_changed_cb (GtkWidget *widget, gpointer user_data)
{
	g_signal_emit_by_name (SSHTUN_PLUGIN_UI_WIDGET (user_data), "changed");
}

static gboolean
init_plugin_ui (SshtunPluginUiWidget *self, NMConnection *connection, GError **error)
{
	SshtunPluginUiWidgetPrivate *priv = SSHTUN_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
	NMSettingVPN *s_vpn;
	GtkWidget *widget;
	GtkListStore *store;
	GtkTreeIter iter;
	int active = -1;
	gboolean is_tap = FALSE;
	const char *value;

	s_vpn = (NMSettingVPN *) nm_connection_get_setting (connection, NM_TYPE_SETTING_VPN);

	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_SSHTUN_KEY_TUN_USE_TAP);
		if (value && !strcmp (value, "yes"))
			is_tap = TRUE;
	}

	priv->group = gtk_size_group_new (GTK_SIZE_GROUP_HORIZONTAL);

	widget = glade_xml_get_widget (priv->xml, "gateway_entry");
	if (!widget)
		return FALSE;
	gtk_size_group_add_widget (priv->group, widget);
	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_SSHTUN_KEY_HOST);
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
	                    COL_TUN_MODE_NAME, _("Point-to-Point"),
	                    COL_TUN_MODE, NM_SSHTUN_TUN_MODE_TUN,
	                    -1);
	if (active == -1 && !is_tap)
		active = 0;
	gtk_list_store_append (store, &iter);
	gtk_list_store_set (store, &iter,
	                    COL_TUN_MODE_NAME, _("Ethernet"),
	                    COL_TUN_MODE, NM_SSHTUN_TUN_MODE_TAP,
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
		value = nm_setting_vpn_get_data_item (s_vpn, NM_SSHTUN_KEY_CONFIG_SCRIPT);
		if (value)
			gtk_entry_set_text (GTK_ENTRY (widget), value);
	}

	widget = glade_xml_get_widget (priv->xml, "user_entry");
	if (!widget)
		return FALSE;
	gtk_size_group_add_widget (priv->group, widget);
	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_SSHTUN_KEY_USER);
		if (value)
			gtk_entry_set_text (GTK_ENTRY (widget), value);
	}
	g_signal_connect (G_OBJECT (widget), "changed", G_CALLBACK (stuff_changed_cb), self);

	widget = glade_xml_get_widget (priv->xml, "public_key_chooser");
	if (!widget)
		return FALSE;
	gtk_size_group_add_widget (priv->group, widget);
	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_SSHTUN_KEY_PUBLIC_KEY);
		if (value)
			gtk_file_chooser_set_filename (GTK_FILE_CHOOSER (widget), value);
	}
	g_signal_connect (G_OBJECT (widget), "selection-changed", G_CALLBACK (stuff_changed_cb), self);

	widget = glade_xml_get_widget (priv->xml, "private_key_chooser");
	if (!widget)
		return FALSE;
	gtk_size_group_add_widget (priv->group, widget);
	if (s_vpn) {
		value = nm_setting_vpn_get_data_item (s_vpn, NM_SSHTUN_KEY_PRIVATE_KEY);
		if (value)
			gtk_file_chooser_set_filename (GTK_FILE_CHOOSER (widget), value);
	}
	g_signal_connect (G_OBJECT (widget), "selection-changed", G_CALLBACK (stuff_changed_cb), self);

	return TRUE;
}

static GObject *
get_widget (NMVpnPluginUiWidgetInterface *iface)
{
	SshtunPluginUiWidget *self = SSHTUN_PLUGIN_UI_WIDGET (iface);
	SshtunPluginUiWidgetPrivate *priv = SSHTUN_PLUGIN_UI_WIDGET_GET_PRIVATE (self);

	return G_OBJECT (priv->widget);
}

static gboolean
update_connection (NMVpnPluginUiWidgetInterface *iface,
                   NMConnection *connection,
                   GError **error)
{
	SshtunPluginUiWidget *self = SSHTUN_PLUGIN_UI_WIDGET (iface);
	SshtunPluginUiWidgetPrivate *priv = SSHTUN_PLUGIN_UI_WIDGET_GET_PRIVATE (self);
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
	g_object_set (s_vpn, NM_SETTING_VPN_SERVICE_TYPE, NM_DBUS_SERVICE_SSHTUN, NULL);

	/* Gateway */
	widget = glade_xml_get_widget (priv->xml, "gateway_entry");
	str = (char *) gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && strlen (str))
		nm_setting_vpn_add_data_item (s_vpn, NM_SSHTUN_KEY_HOST, str);

	/* Tunnel mode */
	widget = glade_xml_get_widget (priv->xml, "tun_mode_combo");
	model = gtk_combo_box_get_model (GTK_COMBO_BOX (widget));
	g_assert (model);
	g_assert (gtk_combo_box_get_active_iter (GTK_COMBO_BOX (widget), &iter));

	gtk_tree_model_get (model, &iter, COL_TUN_MODE, &tun_mode, -1);
	nm_setting_vpn_add_data_item (s_vpn, NM_SSHTUN_KEY_TUN_USE_TAP,
								  tun_mode == NM_SSHTUN_TUN_MODE_TAP
								  ? "yes" : "no");

	/* Config script */
	widget = glade_xml_get_widget (priv->xml, "config_script_entry");
	str = (char *) gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && strlen (str))
		nm_setting_vpn_add_data_item (s_vpn, NM_SSHTUN_KEY_CONFIG_SCRIPT, str);

	/* SSH user */
	widget = glade_xml_get_widget (priv->xml, "user_entry");
	str = (char *) gtk_entry_get_text (GTK_ENTRY (widget));
	if (str && strlen (str))
		nm_setting_vpn_add_data_item (s_vpn, NM_SSHTUN_KEY_USER, str);

	/* SSH public key */
	widget = glade_xml_get_widget (priv->xml, "public_key_chooser");
	str = (char *) gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (widget));
	if (str && strlen (str))
		nm_setting_vpn_add_data_item (s_vpn, NM_SSHTUN_KEY_PUBLIC_KEY, str);

	/* SSH private key */
	widget = glade_xml_get_widget (priv->xml, "private_key_chooser");
	str = (char *) gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (widget));
	if (str && strlen (str))
		nm_setting_vpn_add_data_item (s_vpn, NM_SSHTUN_KEY_PRIVATE_KEY, str);

	nm_connection_add_setting (connection, NM_SETTING (s_vpn));
	valid = TRUE;

	return valid;
}

static gboolean
save_secrets (NMVpnPluginUiWidgetInterface *iface,
              NMConnection *connection,
              GError **error)
{
	return TRUE;
}

static NMVpnPluginUiWidgetInterface *
nm_vpn_plugin_ui_widget_interface_new (NMConnection *connection, GError **error)
{
	NMVpnPluginUiWidgetInterface *object;
	SshtunPluginUiWidgetPrivate *priv;
	char *glade_file;

	if (error)
		g_return_val_if_fail (*error == NULL, NULL);

	object = NM_VPN_PLUGIN_UI_WIDGET_INTERFACE (g_object_new (SSHTUN_TYPE_PLUGIN_UI_WIDGET, NULL));
	if (!object) {
		g_set_error (error, SSHTUN_PLUGIN_UI_ERROR, 0, "could not create sshtun object");
		return NULL;
	}

	priv = SSHTUN_PLUGIN_UI_WIDGET_GET_PRIVATE (object);

	glade_file = g_strdup_printf ("%s/%s", GLADEDIR, "nm-sshtun-dialog.glade");
	priv->xml = glade_xml_new (glade_file, "sshtun-vbox", GETTEXT_PACKAGE);
	if (priv->xml == NULL) {
		g_set_error (error, SSHTUN_PLUGIN_UI_ERROR, 0,
		             "could not load required resources at %s", glade_file);
		g_free (glade_file);
		g_object_unref (object);
		return NULL;
	}
	g_free (glade_file);

	priv->widget = glade_xml_get_widget (priv->xml, "sshtun-vbox");
	if (!priv->widget) {
		g_set_error (error, SSHTUN_PLUGIN_UI_ERROR, 0, "could not load UI widget");
		g_object_unref (object);
		return NULL;
	}
	g_object_ref_sink (priv->widget);

	priv->window_group = gtk_window_group_new ();

	if (!init_plugin_ui (SSHTUN_PLUGIN_UI_WIDGET (object), connection, error)) {
		g_object_unref (object);
		return NULL;
	}

	return object;
}

static void
dispose (GObject *object)
{
	SshtunPluginUiWidget *plugin = SSHTUN_PLUGIN_UI_WIDGET (object);
	SshtunPluginUiWidgetPrivate *priv = SSHTUN_PLUGIN_UI_WIDGET_GET_PRIVATE (plugin);

	if (priv->group)
		g_object_unref (priv->group);

	if (priv->window_group)
		g_object_unref (priv->window_group);

	if (priv->widget)
		g_object_unref (priv->widget);

	if (priv->xml)
		g_object_unref (priv->xml);

	G_OBJECT_CLASS (sshtun_plugin_ui_widget_parent_class)->dispose (object);
}

static void
sshtun_plugin_ui_widget_class_init (SshtunPluginUiWidgetClass *req_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (req_class);

	g_type_class_add_private (req_class, sizeof (SshtunPluginUiWidgetPrivate));

	object_class->dispose = dispose;
}

static void
sshtun_plugin_ui_widget_init (SshtunPluginUiWidget *plugin)
{
}

static void
sshtun_plugin_ui_widget_interface_init (NMVpnPluginUiWidgetInterface *iface_class)
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
		g_value_set_string (value, SSHTUN_PLUGIN_NAME);
		break;
	case NM_VPN_PLUGIN_UI_INTERFACE_PROP_DESC:
		g_value_set_string (value, SSHTUN_PLUGIN_DESC);
		break;
	case NM_VPN_PLUGIN_UI_INTERFACE_PROP_SERVICE:
		g_value_set_string (value, SSHTUN_PLUGIN_SERVICE);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
sshtun_plugin_ui_class_init (SshtunPluginUiClass *req_class)
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
sshtun_plugin_ui_init (SshtunPluginUi *plugin)
{
}

static void
sshtun_plugin_ui_interface_init (NMVpnPluginUiInterface *iface_class)
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

	return NM_VPN_PLUGIN_UI_INTERFACE (g_object_new (SSHTUN_TYPE_PLUGIN_UI, NULL));
}

