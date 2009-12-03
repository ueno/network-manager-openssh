/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/***************************************************************************
 * nm-openssh.h : GNOME UI dialogs for configuring openssh VPN connections
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

#ifndef _NM_OPENSSH_H_
#define _NM_OPENSSH_H_

#include <glib-object.h>

typedef enum
{
	OPENSSH_PLUGIN_UI_ERROR_UNKNOWN = 0,
	OPENSSH_PLUGIN_UI_ERROR_INVALID_CONNECTION,
	OPENSSH_PLUGIN_UI_ERROR_INVALID_PROPERTY,
	OPENSSH_PLUGIN_UI_ERROR_MISSING_PROPERTY,
	OPENSSH_PLUGIN_UI_ERROR_FILE_NOT_READABLE
} OpensshPluginUiError;

#define OPENSSH_TYPE_PLUGIN_UI_ERROR (openssh_plugin_ui_error_get_type ()) 
GType openssh_plugin_ui_error_get_type (void);

#define OPENSSH_PLUGIN_UI_ERROR (openssh_plugin_ui_error_quark ())
GQuark openssh_plugin_ui_error_quark (void);


#define OPENSSH_TYPE_PLUGIN_UI            (openssh_plugin_ui_get_type ())
#define OPENSSH_PLUGIN_UI(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), OPENSSH_TYPE_PLUGIN_UI, OpensshPluginUi))
#define OPENSSH_PLUGIN_UI_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), OPENSSH_TYPE_PLUGIN_UI, OpensshPluginUiClass))
#define OPENSSH_IS_PLUGIN_UI(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), OPENSSH_TYPE_PLUGIN_UI))
#define OPENSSH_IS_PLUGIN_UI_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), OPENSSH_TYPE_PLUGIN_UI))
#define OPENSSH_PLUGIN_UI_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), OPENSSH_TYPE_PLUGIN_UI, OpensshPluginUiClass))

typedef struct _OpensshPluginUi OpensshPluginUi;
typedef struct _OpensshPluginUiClass OpensshPluginUiClass;

struct _OpensshPluginUi {
	GObject parent;
};

struct _OpensshPluginUiClass {
	GObjectClass parent;
};

GType openssh_plugin_ui_get_type (void);


#define OPENSSH_TYPE_PLUGIN_UI_WIDGET            (openssh_plugin_ui_widget_get_type ())
#define OPENSSH_PLUGIN_UI_WIDGET(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), OPENSSH_TYPE_PLUGIN_UI_WIDGET, OpensshPluginUiWidget))
#define OPENSSH_PLUGIN_UI_WIDGET_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), OPENSSH_TYPE_PLUGIN_UI_WIDGET, OpensshPluginUiWidgetClass))
#define OPENSSH_IS_PLUGIN_UI_WIDGET(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), OPENSSH_TYPE_PLUGIN_UI_WIDGET))
#define OPENSSH_IS_PLUGIN_UI_WIDGET_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), OPENSSH_TYPE_PLUGIN_UI_WIDGET))
#define OPENSSH_PLUGIN_UI_WIDGET_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), OPENSSH_TYPE_PLUGIN_UI_WIDGET, OpensshPluginUiWidgetClass))

typedef struct _OpensshPluginUiWidget OpensshPluginUiWidget;
typedef struct _OpensshPluginUiWidgetClass OpensshPluginUiWidgetClass;

struct _OpensshPluginUiWidget {
	GObject parent;
};

struct _OpensshPluginUiWidgetClass {
	GObjectClass parent;
};

GType openssh_plugin_ui_widget_get_type (void);

#endif	/* _NM_OPENSSH_H_ */

