/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */

/* NetworkManager-sshtun -- Tunnel over SSH VPN plugin for NetworkManager.
 * Copyright (C) 2009  Daiki Ueno
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

#ifndef SSHTUN_H
#define SSHTUN_H

#include <sys/types.h>

typedef enum {
	SSHTUN_PARAM_TUN_MODE = 1,
	SSHTUN_PARAM_TUN_OWNER,
	SSHTUN_PARAM_USER,
	SSHTUN_PARAM_HOST,
	SSHTUN_PARAM_SERVICE,
	SSHTUN_PARAM_PUBLIC_KEY,
	SSHTUN_PARAM_PRIVATE_KEY,
	SSHTUN_PARAM_CONFIG_SCRIPT,

	/* Read-only params. */
	SSHTUN_PARAM_TUN_DEV,
	SSHTUN_PARAM_ADDR,
	SSHTUN_PARAM_PEER_ADDR,
	SSHTUN_PARAM_GW_ADDR,
	SSHTUN_PARAM_NETMASK,
	SSHTUN_PARAM_MTU
} sshtun_param_t;

typedef enum {
	SSHTUN_STATE_INITIALIZED,
	SSHTUN_STATE_CONNECTED,
	SSHTUN_STATE_CONFIGURING,
	SSHTUN_STATE_CONFIGURED,
	SSHTUN_STATE_STOPPED
} sshtun_state_t;

typedef struct sshtun_common_st *sshtun_handle_t;

int sshtun_new (sshtun_handle_t *);
void sshtun_del (sshtun_handle_t);
int sshtun_start (sshtun_handle_t);
int sshtun_stop (sshtun_handle_t);
int sshtun_set_params (sshtun_handle_t, ...);
const char *sshtun_get_param (sshtun_handle_t, sshtun_param_t);
pid_t sshtun_pid (sshtun_handle_t);
int sshtun_event_fd (sshtun_handle_t);
int sshtun_dispatch_event (sshtun_handle_t);
sshtun_state_t sshtun_state (sshtun_handle_t);

#endif	/* SSHTUN_H */
