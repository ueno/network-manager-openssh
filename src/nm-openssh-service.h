/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* nm-openssh-service - OpenSSH VPN integration with NetworkManager
 *
 * Copyright (C) 2005 - 2008 Tim Niemueller <tim@niemueller.de>
 * Copyright (C) 2005 - 2008 Dan Williams <dcbw@redhat.com>
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
 */

#ifndef NM_OPENSSH_SERVICE_H
#define NM_OPENSSH_SERVICE_H

#include <glib.h>
#include <glib-object.h>
#include <nm-vpn-plugin.h>

#define NM_TYPE_OPENSSH_PLUGIN            (nm_openssh_plugin_get_type ())
#define NM_OPENSSH_PLUGIN(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_OPENSSH_PLUGIN, NMOpensshPlugin))
#define NM_OPENSSH_PLUGIN_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_OPENSSH_PLUGIN, NMOpensshPluginClass))
#define NM_IS_OPENSSH_PLUGIN(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_OPENSSH_PLUGIN))
#define NM_IS_OPENSSH_PLUGIN_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_OPENSSH_PLUGIN))
#define NM_OPENSSH_PLUGIN_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_OPENSSH_PLUGIN, NMOpensshPluginClass))

#define NM_DBUS_SERVICE_OPENSSH    "org.freedesktop.NetworkManager.openssh"
#define NM_DBUS_INTERFACE_OPENSSH  "org.freedesktop.NetworkManager.openssh"
#define NM_DBUS_PATH_OPENSSH       "/org/freedesktop/NetworkManager/openssh"

#define NM_OPENSSH_KEY_TUN_USE_TAP "use-tap"
#define NM_OPENSSH_KEY_CONFIG_SCRIPT "config-script"
#define NM_OPENSSH_KEY_USER "user"
#define NM_OPENSSH_KEY_HOST "host"
#define NM_OPENSSH_KEY_PUBLIC_KEY "public-key"
#define NM_OPENSSH_KEY_PRIVATE_KEY "private-key"
#define NM_OPENSSH_KEY_PASSWORD "password"

#define NM_OPENSSH_KEY_NOSECRET "no-secret"

#define NM_OPENSSH_TUN_MODE_TUN 0
#define NM_OPENSSH_TUN_MODE_TAP 1

typedef struct {
	NMVPNPlugin parent;
} NMOpensshPlugin;

typedef struct {
	NMVPNPluginClass parent;
} NMOpensshPluginClass;

GType nm_openssh_plugin_get_type (void);

NMOpensshPlugin *nm_openssh_plugin_new (void);

#endif /* NM_OPENSSH_SERVICE_H */
