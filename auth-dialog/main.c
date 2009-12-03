/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager Wireless Applet -- Display wireless access points and allow user control
 *
 * Dan Williams <dcbw@redhat.com>
 * Tim Niemueller <tim@niemueller.de>
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
 * (C) Copyright 2004 - 2008 Red Hat, Inc.
 *               2005 Tim Niemueller [www.niemueller.de]
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>
#include <stdlib.h>
#include <glib/gi18n.h>
#include <gtk/gtk.h>
#include <gconf/gconf-client.h>
#include <gnome-keyring.h>
#include <nm-setting-vpn.h>
#include <nm-setting-connection.h>

#include "common-gnome/keyring-helpers.h"
#include "src/nm-openssh-service.h"
#include "gnome-two-password-dialog.h"

typedef struct {
	char *vpn_uuid;
	char *vpn_name;

	gboolean need_password;
	char *password;
} PasswordsInfo;

static void
clear_secrets (PasswordsInfo *info)
{
	if (info->password) {
		memset (info->password, 0, strlen (info->password));
		g_free (info->password);
	}
}

static gboolean
get_secrets (PasswordsInfo *info, gboolean retry)
{
	GnomeTwoPasswordDialog *dialog;
	gboolean is_session = TRUE;
	char *prompt;
	gboolean success = FALSE, need_secret = FALSE;

	g_return_val_if_fail (info->vpn_uuid != NULL, FALSE);
	g_return_val_if_fail (info->vpn_name != NULL, FALSE);

	if (info->need_password) {
		info->password = keyring_helpers_lookup_secret (info->vpn_uuid, NM_OPENSSH_KEY_PASSWORD, &is_session);
		if (!info->password)
			need_secret = TRUE;
	}

	/* Have all passwords and we're not supposed to ask the user again */
	if (!need_secret && !retry)
		return TRUE;

	prompt = g_strdup_printf (_("You need to authenticate to access the Virtual Private Network '%s'."), info->vpn_name);
	dialog = GNOME_TWO_PASSWORD_DIALOG (gnome_two_password_dialog_new (_("Authenticate VPN"), prompt, NULL, NULL, FALSE));
	g_free (prompt);

	gnome_two_password_dialog_set_show_username (dialog, FALSE);
	gnome_two_password_dialog_set_show_userpass_buttons (dialog, FALSE);
	gnome_two_password_dialog_set_show_domain (dialog, FALSE);
	gnome_two_password_dialog_set_show_remember (dialog, TRUE);

	/* If nothing was found in the keyring, default to not remembering any secrets */
	if (info->password) {
		/* Otherwise set default remember based on which keyring the secrets were found in */
		if (is_session)
			gnome_two_password_dialog_set_remember (dialog, GNOME_TWO_PASSWORD_DIALOG_REMEMBER_SESSION);
		else
			gnome_two_password_dialog_set_remember (dialog, GNOME_TWO_PASSWORD_DIALOG_REMEMBER_FOREVER);
	} else
		gnome_two_password_dialog_set_remember (dialog, GNOME_TWO_PASSWORD_DIALOG_REMEMBER_NOTHING);

	/* pre-fill dialog with the password */
	if (info->need_password) {
		gnome_two_password_dialog_set_show_password_secondary (dialog, TRUE);
		gnome_two_password_dialog_set_password_secondary_label (dialog, _("Certificate pass_word:") );

		/* if retrying, put in the passwords from the keyring */
		if (info->password)
			gnome_two_password_dialog_set_password (dialog, info->password);
	} else {
		gnome_two_password_dialog_set_show_password_secondary (dialog, FALSE);
		if (info->need_password) {
			/* if retrying, put in the passwords from the keyring */
			if (info->password)
				gnome_two_password_dialog_set_password (dialog, info->password);
		}
	}
	clear_secrets (info);

	gtk_widget_show (GTK_WIDGET (dialog));

	if (gnome_two_password_dialog_run_and_block (dialog)) {
		gboolean save = FALSE;
		char *keyring = NULL;

		if (info->need_password)
			info->password = g_strdup (gnome_two_password_dialog_get_password (dialog));

		switch (gnome_two_password_dialog_get_remember (dialog)) {
		case GNOME_TWO_PASSWORD_DIALOG_REMEMBER_SESSION:
			keyring = "session";
			/* Fall through */
		case GNOME_TWO_PASSWORD_DIALOG_REMEMBER_FOREVER:
			save = TRUE;
			break;
		default:
			break;
		}

		if (save) {
			if (info->password) {
				keyring_helpers_save_secret (info->vpn_uuid, info->vpn_name,
											 keyring, NM_OPENSSH_KEY_PASSWORD, info->password);
			}
		}

		success = TRUE;
	}

	gtk_widget_destroy (GTK_WIDGET (dialog));

	return success;
}

static gboolean
get_password_types (PasswordsInfo *info)
{
	info->need_password = TRUE;

	return TRUE;
}

 int 
	 main (int argc, char *argv[])
 {
	 PasswordsInfo info;
	 gboolean retry = FALSE;
	 gchar *vpn_name = NULL;
	 gchar *vpn_uuid = NULL;
	 gchar *vpn_service = NULL;
	 char buf[1];
	 int ret;
	 GOptionContext *context;
	 GOptionEntry entries[] = {
		 { "reprompt", 'r', 0, G_OPTION_ARG_NONE, &retry, "Reprompt for passwords", NULL},
		 { "uuid", 'u', 0, G_OPTION_ARG_STRING, &vpn_uuid, "UUID of VPN connection", NULL},
		 { "name", 'n', 0, G_OPTION_ARG_STRING, &vpn_name, "Name of VPN connection", NULL},
		 { "service", 's', 0, G_OPTION_ARG_STRING, &vpn_service, "VPN service type", NULL},
		 { NULL }
	 };

	 bindtextdomain (GETTEXT_PACKAGE, NULL);
	 bind_textdomain_codeset (GETTEXT_PACKAGE, "UTF-8");
	 textdomain (GETTEXT_PACKAGE);

	 gtk_init (&argc, &argv);

	 context = g_option_context_new ("- sshtun auth dialog");
	 g_option_context_add_main_entries (context, entries, GETTEXT_PACKAGE);
	 g_option_context_parse (context, &argc, &argv, NULL);
	 g_option_context_free (context);

	 if (vpn_uuid == NULL || vpn_name == NULL || vpn_service == NULL) {
		 fprintf (stderr, "Have to supply ID, name, and service\n");
		 return EXIT_FAILURE;
	 }

	 if (strcmp (vpn_service, NM_DBUS_SERVICE_OPENSSH) != 0) {
		 fprintf (stderr, "This dialog only works with the '%s' service\n", NM_DBUS_SERVICE_OPENSSH);
		 return EXIT_FAILURE;
	 }

	 memset (&info, 0, sizeof (PasswordsInfo));
	 info.vpn_uuid = vpn_uuid;
	 info.vpn_name = vpn_name;

	 if (!get_password_types (&info)) {
		 fprintf (stderr, "Invalid connection");
		 return EXIT_FAILURE;
	 }

	 if (!info.need_password) {
		 printf ("%s\n%s\n\n\n", NM_OPENSSH_KEY_NOSECRET, "true");
		 return EXIT_SUCCESS;
	 }

	 if (get_secrets (&info, retry)) {
		 if (info.need_password)
			 printf ("%s\n%s\n", NM_OPENSSH_KEY_PASSWORD, info.password);
	 }
	 printf ("\n\n");

	 clear_secrets (&info);

	 /* for good measure, flush stdout since Kansas is going Bye-Bye */
	 fflush (stdout);

	 /* wait for data on stdin  */
	 ret = fread (buf, sizeof (char), sizeof (buf), stdin);


	return EXIT_SUCCESS;
 }
