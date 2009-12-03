/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/***************************************************************************
 * nm-sshtun.h : GNOME UI dialogs for configuring sshtun VPN connections
 *
 * Copyright (C) 2008 Dan Williams, <dcbw@redhat.com>
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

#ifndef _NM_SSHTUN_H_
#define _NM_SSHTUN_H_

#include <glib-object.h>

typedef enum
{
	SSHTUN_PLUGIN_UI_ERROR_UNKNOWN = 0,
	SSHTUN_PLUGIN_UI_ERROR_INVALID_CONNECTION,
	SSHTUN_PLUGIN_UI_ERROR_INVALID_PROPERTY,
	SSHTUN_PLUGIN_UI_ERROR_MISSING_PROPERTY,
	SSHTUN_PLUGIN_UI_ERROR_FILE_NOT_READABLE
} SshtunPluginUiError;

#define SSHTUN_TYPE_PLUGIN_UI_ERROR (sshtun_plugin_ui_error_get_type ()) 
GType sshtun_plugin_ui_error_get_type (void);

#define SSHTUN_PLUGIN_UI_ERROR (sshtun_plugin_ui_error_quark ())
GQuark sshtun_plugin_ui_error_quark (void);


#define SSHTUN_TYPE_PLUGIN_UI            (sshtun_plugin_ui_get_type ())
#define SSHTUN_PLUGIN_UI(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), SSHTUN_TYPE_PLUGIN_UI, SshtunPluginUi))
#define SSHTUN_PLUGIN_UI_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), SSHTUN_TYPE_PLUGIN_UI, SshtunPluginUiClass))
#define SSHTUN_IS_PLUGIN_UI(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SSHTUN_TYPE_PLUGIN_UI))
#define SSHTUN_IS_PLUGIN_UI_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), SSHTUN_TYPE_PLUGIN_UI))
#define SSHTUN_PLUGIN_UI_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), SSHTUN_TYPE_PLUGIN_UI, SshtunPluginUiClass))

typedef struct _SshtunPluginUi SshtunPluginUi;
typedef struct _SshtunPluginUiClass SshtunPluginUiClass;

struct _SshtunPluginUi {
	GObject parent;
};

struct _SshtunPluginUiClass {
	GObjectClass parent;
};

GType sshtun_plugin_ui_get_type (void);


#define SSHTUN_TYPE_PLUGIN_UI_WIDGET            (sshtun_plugin_ui_widget_get_type ())
#define SSHTUN_PLUGIN_UI_WIDGET(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), SSHTUN_TYPE_PLUGIN_UI_WIDGET, SshtunPluginUiWidget))
#define SSHTUN_PLUGIN_UI_WIDGET_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), SSHTUN_TYPE_PLUGIN_UI_WIDGET, SshtunPluginUiWidgetClass))
#define SSHTUN_IS_PLUGIN_UI_WIDGET(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SSHTUN_TYPE_PLUGIN_UI_WIDGET))
#define SSHTUN_IS_PLUGIN_UI_WIDGET_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), SSHTUN_TYPE_PLUGIN_UI_WIDGET))
#define SSHTUN_PLUGIN_UI_WIDGET_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), SSHTUN_TYPE_PLUGIN_UI_WIDGET, SshtunPluginUiWidgetClass))

typedef struct _SshtunPluginUiWidget SshtunPluginUiWidget;
typedef struct _SshtunPluginUiWidgetClass SshtunPluginUiWidgetClass;

struct _SshtunPluginUiWidget {
	GObject parent;
};

struct _SshtunPluginUiWidgetClass {
	GObjectClass parent;
};

GType sshtun_plugin_ui_widget_get_type (void);

#endif	/* _NM_SSHTUN_H_ */

