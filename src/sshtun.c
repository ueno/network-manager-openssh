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

#include <libssh2.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/wait.h>

#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#include <stddef.h>
#include <stdarg.h>

#include <pwd.h>
#include <poll.h>
#include "sshtun.h"

#define TUN_CLONE_DEVICE "/dev/net/tun"
#define SSH_TUN_CHANNEL_TYPE "tun@openssh.com"
#define SSH_TUNMODE_POINTOPOINT 1
#define SSH_TUNMODE_ETHERNET 2
#define SSH_TUN_AF_INET 2
#define SSH_TUN_AF_INET6 24
#define SSH_TUNID_ANY 0x7FFFFFFF

#ifdef SSHTUN_DEBUG
#define DBG(...) fprintf (stderr, __VA_ARGS__)
#else
#define DBG(...)
#endif

struct sshtun_params_st {
	/* Read-write parameters. */
	char *tun_mode;				/* Tunnel mode (pointopoint or ethernet) */
	char *tun_owner;			/* Tunnel device owner */
	char *user;					/* SSH user name (optional) */
	char *host;					/* SSH remote host */
	char *service;				/* SSH remote service (optional) */
	char *public_key;			/* SSH public key file (optional) */
	char *private_key;			/* SSH private key file */
	char *config_script; /* Remote path of an IP config script (optional) */

	/* Read-only parameters set after a connection is established. */
	char *tun_dev;				/* Tunnel device */
	/* IP configuration sent by the peer. */
	char *addr;			  /* Local address assigned to the tunnel */
	char *peer_addr;	  /* Address of the other end of the tunnel */
	char *gw_addr;		  /* Gateway address */
	char *netmask;		  /* Netmask */
	char *mtu;			  /* MTU */
};

enum param_flag {
	PARAM_FLAG_READ = 1,
	PARAM_FLAG_WRITE = 2,
	PARAM_FLAG_REQUIRED = 4
};

enum param_type {
	PARAM_TYPE_ADDR = 1,
	PARAM_TYPE_INT = 2,
	PARAM_TYPE_STRING = 4
};

static const struct {
	sshtun_param_t param;
	size_t offset;
	enum param_flag flags;
	enum param_type type;
} sshtun_param_defs[] = {
	{SSHTUN_PARAM_TUN_MODE, offsetof(struct sshtun_params_st, tun_mode),
	 PARAM_FLAG_READ | PARAM_FLAG_WRITE | PARAM_FLAG_REQUIRED,
	 PARAM_TYPE_STRING},
	{SSHTUN_PARAM_TUN_OWNER, offsetof(struct sshtun_params_st, tun_owner),
	 PARAM_FLAG_READ | PARAM_FLAG_WRITE | PARAM_FLAG_REQUIRED,
	 PARAM_TYPE_STRING},
	{SSHTUN_PARAM_USER, offsetof(struct sshtun_params_st, user),
	 PARAM_FLAG_READ | PARAM_FLAG_WRITE, PARAM_TYPE_STRING},
	{SSHTUN_PARAM_HOST, offsetof(struct sshtun_params_st, host),
	 PARAM_FLAG_READ | PARAM_FLAG_WRITE | PARAM_FLAG_REQUIRED,
	 PARAM_TYPE_STRING},
	{SSHTUN_PARAM_SERVICE, offsetof(struct sshtun_params_st, service),
	 PARAM_FLAG_READ | PARAM_FLAG_WRITE | PARAM_FLAG_REQUIRED,
	 PARAM_TYPE_STRING},
	{SSHTUN_PARAM_PUBLIC_KEY, offsetof(struct sshtun_params_st, public_key),
	 PARAM_FLAG_READ | PARAM_FLAG_WRITE, PARAM_TYPE_STRING},
	{SSHTUN_PARAM_PRIVATE_KEY, offsetof(struct sshtun_params_st, private_key),
	 PARAM_FLAG_READ | PARAM_FLAG_WRITE | PARAM_FLAG_REQUIRED,
	 PARAM_TYPE_STRING},
	{SSHTUN_PARAM_CONFIG_SCRIPT,
	 offsetof(struct sshtun_params_st, config_script),
	 PARAM_FLAG_READ | PARAM_FLAG_WRITE | PARAM_FLAG_REQUIRED,
	 PARAM_TYPE_STRING},
	{SSHTUN_PARAM_TUN_DEV, offsetof(struct sshtun_params_st, tun_dev),
	 PARAM_FLAG_READ, PARAM_TYPE_STRING},
	{SSHTUN_PARAM_ADDR, offsetof(struct sshtun_params_st, addr),
	 PARAM_FLAG_READ, PARAM_TYPE_ADDR},
	{SSHTUN_PARAM_PEER_ADDR, offsetof(struct sshtun_params_st, peer_addr),
	 PARAM_FLAG_READ, PARAM_TYPE_ADDR},
	{SSHTUN_PARAM_GW_ADDR, offsetof(struct sshtun_params_st, gw_addr),
	 PARAM_FLAG_READ, PARAM_TYPE_ADDR},
	{SSHTUN_PARAM_NETMASK, offsetof(struct sshtun_params_st, netmask),
	 PARAM_FLAG_READ, PARAM_TYPE_ADDR},
	{SSHTUN_PARAM_MTU, offsetof(struct sshtun_params_st, mtu),
	 PARAM_FLAG_READ, PARAM_TYPE_INT}
};

#define NPARAMS (sizeof sshtun_param_defs / sizeof sshtun_param_defs[0])

struct sshtun_event_fd_st {
	int fd;
	char buffer[BUFSIZ];
	size_t offset, length;
};

struct sshtun_tun_fd_st {
	int fd;
	int mode;
};

struct sshtun_ssh_fd_st {
	int fd;
	LIBSSH2_CHANNEL *channel;
};

struct sshtun_common_st {
	struct sshtun_params_st params;
	struct sshtun_event_fd_st event_rfd, event_wfd;
	int tun_mode;
};

struct sshtun_parent_st {
	struct sshtun_common_st common;
	pid_t pid;
	sshtun_state_t state;
};

struct sshtun_child_st {
	struct sshtun_common_st common;
	int tun_fd;
	struct addrinfo *ai;
	int tcp_fd;
	LIBSSH2_CHANNEL *ssh_channel;
	LIBSSH2_SESSION *ssh_session;
};

static int open_tun (struct ifreq *, const char *, int);
static int open_tcp (struct addrinfo **, const char *, const char *);
static int open_ssh (LIBSSH2_CHANNEL **, LIBSSH2_SESSION **, int, const char *,
					 const char *, const char *, const char *, int,
					 const char *, struct sshtun_event_fd_st *);
static int start_proxy (struct sshtun_tun_fd_st *,
						struct sshtun_ssh_fd_st *,
						struct sshtun_event_fd_st *,
						struct sshtun_event_fd_st *);

static char *
recv_event_from_buffer (struct sshtun_event_fd_st *event_rfd)
{
	char *s, *p;

	if (event_rfd->offset == event_rfd->length)
		return NULL;

	s = event_rfd->buffer + event_rfd->offset;
	p = memchr (s, '\n', event_rfd->length - event_rfd->offset);
	if (!p) {
		if (event_rfd->length == sizeof event_rfd->buffer)
			event_rfd->offset = event_rfd->length = 0;
		else {
			memmove (event_rfd->buffer, event_rfd->buffer + event_rfd->offset,
					 event_rfd->offset);
			event_rfd->length -= event_rfd->offset;
			event_rfd->offset = 0;
		}
		return NULL;
	}

	*p++ = '\0';
	event_rfd->offset = p - event_rfd->buffer;
	return s;
}

static char *
recv_event (struct sshtun_event_fd_st *event_rfd)
{
	char *p;
	int ret;

	p = recv_event_from_buffer (event_rfd);
	if (p)
		return p;

	do {
		ret = read (event_rfd->fd, event_rfd->buffer + event_rfd->offset,
					sizeof event_rfd->buffer - event_rfd->length);
	} while (ret == -1 && errno == EINTR);
	if (ret == -1) {
		event_rfd->offset = event_rfd->length = 0;
		return NULL;
	}
	if (ret == 0) {
		if (event_rfd->offset == event_rfd->length)
			return NULL;
		event_rfd->buffer[event_rfd->length] = '\0';
		return event_rfd->buffer + event_rfd->offset;
	}
	event_rfd->length += ret;
	return recv_event_from_buffer (event_rfd);
}

static int
send_event (struct sshtun_event_fd_st *event_wfd, const char *data)
{
	size_t offset, length;
	int ret;

	length = strlen (data);
	if (length >= sizeof event_wfd->buffer - 2)
		return -1;
	memcpy (event_wfd->buffer, data, length);
	event_wfd->buffer[length] = '\n';
	event_wfd->offset = 0;
	event_wfd->length = length + 1;

	for (offset = 0; offset < event_wfd->length; ) {
		ret = write (event_wfd->fd, event_wfd->buffer + event_wfd->offset,
					 event_wfd->length - event_wfd->offset);
		if (ret == -1) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		offset += ret;
		event_wfd->offset += ret;
	}
	return 0;
}

static void
deinit_params (struct sshtun_params_st *params)
{
	int i;

	if (!params)
		return;

	for (i = 0; i < NPARAMS; i++) {
		char **address = (void *)params + sshtun_param_defs[i].offset;
		free (*address);
	}
}

static int
set_param (struct sshtun_params_st *params, sshtun_param_t param,
		   const char *value, int force)
{
	int i;

	for (i = 0; i < NPARAMS; i++) {
		if (sshtun_param_defs[i].param == param) {
			char *p, **address;

			if (!force && (sshtun_param_defs[i].flags & PARAM_FLAG_WRITE) == 0)
				return -1;

			p = strdup (value);
			if (!p)
				return -1;
			address = (void *)params + sshtun_param_defs[i].offset;
			*address = p;
			return 0;
		}
	}
	if (i == NPARAMS)
		return -1;
	return 0;
}

static int
check_params (struct sshtun_params_st *params)
{
	int i;

	if (!params)
		return -1;

	for (i = 0; i < NPARAMS; i++) {
		char **address;

		address = (void *)params + sshtun_param_defs[i].offset;
		if ((sshtun_param_defs[i].flags & PARAM_FLAG_REQUIRED) && !*address)
			return -1;
	}
	if (strcmp (params->tun_mode, "pointopoint")
		&& strcmp (params->tun_mode, "ethernet")) {
		DBG("invalid tunnel mode: %s\n", params->tun_mode);
		return -1;
	}

	return 0;
}

static void
init_common (sshtun_handle_t handle) {
	handle->event_rfd.fd = -1;
	handle->event_wfd.fd = -1;
}

static void
stop_common (sshtun_handle_t handle) {
	if (handle->event_rfd.fd >= 0) {
		close (handle->event_rfd.fd);
		handle->event_rfd.fd = -1;
	}
	if (handle->event_wfd.fd >= 0) {
		close (handle->event_wfd.fd);
		handle->event_wfd.fd = -1;
	}
}

static int
init_child (struct sshtun_child_st *handle)
{
	memset (handle, 0, sizeof *handle);
	init_common ((sshtun_handle_t)handle);
	handle->tun_fd = -1;
	handle->tcp_fd = -1;
	return 0;
}

static int
start_child (struct sshtun_child_st *child)
{
	sshtun_handle_t handle;
	struct ifreq ifr;
	char *password = NULL;
	struct pollfd pfd;
	int ret;
	struct sshtun_tun_fd_st tun_fd;
	struct sshtun_ssh_fd_st ssh_fd;

	handle = (sshtun_handle_t)child;
	child->tun_fd = open_tun (&ifr, handle->params.tun_dev, handle->tun_mode);
	if (!child->tun_fd)
		return -1;
	send_event (&handle->event_wfd, "TUN_OPEN");
	child->tcp_fd = open_tcp (&child->ai,
							  handle->params.host,
							  handle->params.service);
	if (!child->tcp_fd) {
		close (child->tun_fd);
		return -1;
	}
	send_event (&handle->event_wfd, "TCP_OPEN");

	/* Wait a second for getting a password from the parent process. */
	send_event (&handle->event_wfd, "NEED_PASSWORD");
	pfd.fd = handle->event_rfd.fd;
	pfd.events = POLLIN;
	ret = poll (&pfd, 1, 1000);
	if (ret < 0)  {
		close (child->tcp_fd);
		close (child->tun_fd);
		return -1;
	}
	if (ret > 0)
		password = recv_event (&handle->event_rfd);
	ret = open_ssh (&child->ssh_channel, &child->ssh_session,
					child->tcp_fd,	handle->params.user,
					handle->params.public_key, handle->params.private_key,
					password ? password : "",
					handle->tun_mode,
					handle->params.config_script,
					&handle->event_wfd);
	if (password)
		memset (password, 0, strlen (password));
	if (ret < 0) {
		close (child->tcp_fd);
		close (child->tun_fd);
		return -1;
	}
	send_event (&handle->event_wfd, "SSH_OPEN");
	send_event (&handle->event_wfd, "START");
	tun_fd.fd = child->tun_fd;
	tun_fd.mode = handle->tun_mode;
	ssh_fd.fd = child->tcp_fd;
	ssh_fd.channel = child->ssh_channel;
	return start_proxy (&tun_fd, &ssh_fd,
						&handle->event_rfd, &handle->event_wfd);
}

static void
stop_child (struct sshtun_child_st *handle)
{
	if (handle->ssh_channel) {
		libssh2_channel_close (handle->ssh_channel);
		libssh2_channel_free (handle->ssh_channel);
		handle->ssh_channel = NULL;
	}
	if (handle->ssh_session) {
		libssh2_session_disconnect (handle->ssh_session, "");
		libssh2_session_free (handle->ssh_session);
		handle->ssh_session = NULL;
	}
	if (handle->tcp_fd >= 0) {
		close (handle->tcp_fd);
		handle->tcp_fd = -1;
	}
	if (handle->ai) {
		freeaddrinfo (handle->ai);
		handle->ai = NULL;
	}
	if (handle->tun_fd >= 0) {
		close (handle->tun_fd);
		handle->tun_fd = -1;
	}
	stop_common ((sshtun_handle_t)handle);
}

static int
init_parent (struct sshtun_parent_st *handle)
{
	memset (handle, 0, sizeof *handle);
	init_common ((sshtun_handle_t)handle);
	handle->pid = -1;
	return 0;
}

static int
open_tcp (struct addrinfo **r_ai, const char *host, const char *service)
{
	struct addrinfo hints, *ai0, *ai;
	int fd;

	memset (&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	if (getaddrinfo (host, service, &hints, &ai0) == -1)
		return -1;

	ai = ai0;
	while (ai) {
		if ((fd = socket (ai->ai_family, ai->ai_socktype, ai->ai_protocol)) < 0
			|| connect (fd, ai->ai_addr, ai->ai_addrlen) == -1) {
			ai0 = ai->ai_next;
			freeaddrinfo (ai);
			ai = ai0;
		} else {
			*r_ai = ai;
			ai = ai->ai_next;
		}
	}

	return fd;
}

static int
open_ssh (LIBSSH2_CHANNEL **r_channel, LIBSSH2_SESSION **r_session,
		  int tcp_fd, const char *user,
		  const char *public_key, const char *private_key, const char *password,
		  int tun_mode, const char *config_script,
		  struct sshtun_event_fd_st *event_wfd)
{
	int ret;
	LIBSSH2_CHANNEL *tun_channel = NULL, *exec_channel = NULL;
	LIBSSH2_SESSION *session;
	char tun_open_message[8], *s, buffer[BUFSIZ];
	uint32_t nl;

	session = libssh2_session_init ();
	libssh2_session_set_blocking (session, 3);
	ret = libssh2_session_startup (session, tcp_fd);
	if (ret < 0) {
		DBG("Can't establish SSH session\n");
		return -1;
	}

#if SSHTUN_DEBUG
	libssh2_trace (session, ~0);
#endif

	ret = libssh2_userauth_publickey_fromfile (session, user,
											   public_key, private_key,
											   password);
	if (ret < 0) {
		DBG("Can't authenticate user %s with %s\n", user, public_key);
		goto shutdown;
	}

	memset (tun_open_message, 0, sizeof tun_open_message);
	s = tun_open_message;
	nl = htonl (tun_mode);
	memcpy (s, &nl, 4);
	s += 4;
	nl = htonl (SSH_TUNID_ANY);
	memcpy (s, &nl, 4);
	s += 4;

	/* Open a channel for tun@openssh.com */
	tun_channel = libssh2_channel_open_ex (session, SSH_TUN_CHANNEL_TYPE,
										   strlen (SSH_TUN_CHANNEL_TYPE),
										   LIBSSH2_CHANNEL_WINDOW_DEFAULT,
										   LIBSSH2_CHANNEL_PACKET_DEFAULT,
										   tun_open_message,
										   sizeof tun_open_message);
	if (!tun_channel)
		goto shutdown;

	/* Run the remote config script */
	exec_channel = libssh2_channel_open_session (session);
	if (!exec_channel)
		goto shutdown;
	if (libssh2_channel_exec (exec_channel, config_script) < 0)
		goto noscript;
	send_event (event_wfd, "BEGIN_CONFIG");
	while (1) {
		char *line_start, *line_end = NULL;

		ret = libssh2_channel_read (exec_channel, buffer, sizeof buffer);

		if (ret < 0) {
			DBG("libssh2_channel_read returned error %d\n", ret);
			break;
		}
		if (ret == 0)
			break;

		buffer[ret] = '\0';
		for (line_start = buffer; *line_start; line_start = line_end) {
			line_end = memchr (line_start, '\n', ret - (line_start - buffer));
			if (!line_end)
				break;
			*line_end++ = '\0';
			send_event (event_wfd, line_start);
		}
		if (line_end && *line_end != '\0') {
			send_event (event_wfd, line_start);
		}
    }
	send_event (event_wfd, "END_CONFIG");

 noscript:
	libssh2_channel_close (exec_channel);
	libssh2_channel_free (exec_channel);
	exec_channel = NULL;

	*r_channel = tun_channel;
	*r_session = session;

	return 0;

 shutdown:
	if (exec_channel) {
		libssh2_channel_close (exec_channel);
		libssh2_channel_free (exec_channel);
	}
	if (tun_channel) {
		libssh2_channel_close (tun_channel);
		libssh2_channel_free (tun_channel);
	}
	libssh2_session_disconnect (session, "");
	libssh2_session_free (session);

	return -1;
}

static int
open_tun (struct ifreq *ifr, const char *dev, int tun_mode)
{
	int fd;

	fd = open (TUN_CLONE_DEVICE, O_RDWR);
	if (fd < 0)
		return -1;

	memset(ifr, 0, sizeof *ifr);
	ifr->ifr_flags = (tun_mode == SSH_TUNMODE_POINTOPOINT ? IFF_TUN : IFF_TAP)
		| IFF_NO_PI;
	if (dev)
		strncpy(ifr->ifr_name, dev, IFNAMSIZ);

	if (ioctl(fd, TUNSETIFF, (void *)ifr) == -1) {
		DBG("TUNSETIFF: %s\n", strerror (errno));
		close (fd);
		return -1;
	}
	return fd;
}

static char *
create_tun (uid_t owner, int tun_mode)
{
	struct ifreq ifr;
	int fd;

	fd = open_tun (&ifr, NULL, tun_mode);
	if (fd < 0)
		return NULL;
	if (ioctl (fd, TUNSETOWNER, owner) == -1) {
		DBG("TUNSETOWNER: %s\n", strerror (errno));
		close (fd);
		return NULL;
	}
	if (ioctl (fd, TUNSETPERSIST, 1) == -1) {
		DBG("TUNSETPERSIST: %s\n", strerror (errno));
		close (fd);
		return NULL;
	}
	close (fd);

	return strdup (ifr.ifr_name);
}

static int
destroy_tun (const char *tun_dev, int tun_mode)
{
	struct ifreq ifr;
	int fd;

	fd = open_tun (&ifr, tun_dev, tun_mode);
	if (fd < 0)
		return -1;
	ioctl (fd, TUNSETPERSIST, 0);
	return close (fd);
}

static int
start_proxy (struct sshtun_tun_fd_st *tun_fd,
			 struct sshtun_ssh_fd_st *ssh_fd,
			 struct sshtun_event_fd_st *event_rfd,
			 struct sshtun_event_fd_st *event_wfd)
{
	struct pollfd pfds[3];
	char buffer[BUFSIZ], *p;
	ssize_t ret;

	pfds[0].fd = tun_fd->fd;
	pfds[1].fd = ssh_fd->fd;
	pfds[2].fd = event_rfd->fd;

	while (1) {
		int nfds;

		pfds[0].events = POLLIN;
		pfds[0].revents = 0;

		pfds[1].events = POLLIN;
		pfds[1].revents = 0;

		pfds[2].events = POLLIN;
		pfds[2].revents = 0;

		nfds = poll (pfds, sizeof pfds / sizeof pfds[0], 1000);
		if (nfds > 0) {
			/* If we detect one of the FD is closed, stop processing. */
			if ((pfds[0].revents | pfds[1].revents | pfds[2].revents)
				& POLLHUP)
				return 0;

			if (pfds[0].revents & POLLIN) {
				/* Keep 4-byte for protocol family used in tun@openssh.com. */
				p = tun_fd->mode == SSH_TUNMODE_POINTOPOINT ? buffer + 4 :
					buffer;
				ret = read (tun_fd->fd, p, sizeof buffer - (p - buffer));
				DBG(">tun -> ssh: %ld\n", ret);
				if (ret < 0) {
					DBG("read from tun: %s\n", strerror (errno));
					break;
				}

				if (ret > 0) {
					if (tun_fd->mode == SSH_TUNMODE_POINTOPOINT) {
						/* Currently only IP is supported. */
						int version = (*p >> 4) & 0xF;
						uint32_t family;

						switch (version) {
						case 0x4:
							family = SSH_TUN_AF_INET;
							break;
						case 0x6:
							family = SSH_TUN_AF_INET6;
							break;
						default:
							DBG("unknown IP version %x, perhaps not IP?\n",
								version);
							return -1;
						}

						family = htonl (family);
						memcpy (buffer, &family, 4);
						p = buffer;
						ret += 4;
					}

					do {
						ret = libssh2_channel_write (ssh_fd->channel, p, ret);
					} while (ret == LIBSSH2_ERROR_EAGAIN);
					DBG("<tun -> ssh: %ld\n", ret);
					if (ret < 0)
						break;
				}
			}
			if (pfds[1].revents & POLLIN) {
				ret = libssh2_channel_read (ssh_fd->channel, buffer,
											sizeof buffer);
				DBG(">ssh -> tun: %ld\n", ret);
				if (ret < 0)
					break;

				if (ret > 0) {
					/* Skip 4-byte protocol family used in tun@openssh.com. */
					if (tun_fd->mode == SSH_TUNMODE_POINTOPOINT) {
						uint32_t family = ntohl (*(uint32_t *)buffer);

						switch (family) {
						case SSH_TUN_AF_INET:
						case SSH_TUN_AF_INET6:
							DBG("protocol family %x\n", family);
							break;
						default:
							return -1;
						}
						p = buffer + 4;
						ret -= 4;
					} else
						p = buffer;

					ret = write (tun_fd->fd, p, ret);
					if (ret < 0) {
						DBG("write to tun: %s\n", strerror (errno));
						break;
					}
					DBG("<ssh -> tun: %ld\n", ret);
				}
			}
		}
	}
	return ret;
}

int
sshtun_new (sshtun_handle_t *r_handle)
{
	struct sshtun_parent_st *handle;

	handle = malloc (sizeof *handle);
	if (!handle)
		return -1;
	init_parent (handle);

	handle->state = SSHTUN_STATE_INITIALIZED;
	*r_handle = (sshtun_handle_t)handle;
	return 0;
}

void
sshtun_del (sshtun_handle_t handle)
{
	if (!handle)
		return;

	deinit_params (&handle->params);
	free (handle);
}

static int
read_addr (const char *node, struct sockaddr *addr)
{
	struct sockaddr_in *in_addr = (struct sockaddr_in *)addr;

	memset (in_addr, 0, sizeof *in_addr);
	in_addr->sin_family = AF_INET;
	in_addr->sin_addr.s_addr = inet_addr (node);

	return 0;
}

static int
add_config (struct sshtun_params_st *params, const char *config)
{
	static const struct {
		const char *prefix;
		sshtun_param_t param;
	} config_defs[] = {
		{"ADDR", SSHTUN_PARAM_ADDR},
		{"PEER_ADDR", SSHTUN_PARAM_PEER_ADDR},
		{"GW_ADDR", SSHTUN_PARAM_GW_ADDR},
		{"NETMASK", SSHTUN_PARAM_NETMASK},
		{"MTU", SSHTUN_PARAM_MTU}
	};
#define NCONFIG sizeof config_defs / sizeof config_defs[0]
	int i;

	for (i = 0; i < NCONFIG; i++) {
		size_t prefix_length = strlen (config_defs[i].prefix);

		if (!strncmp (config_defs[i].prefix, config, prefix_length)) {
			int j;

			for (j = prefix_length; config[j] == ' '; j++)
				;

			if (config[j] != '\0')
				return set_param (params, config_defs[i].param, &config[j], 1);
		}
	}
	if (i == NCONFIG) {
		DBG("unknown config prefix: %s\n", config);
		return -1;
	}
	return 0;
}

static int
config_tun (struct sshtun_params_st *params, int tun_mode)
{
	struct ifreq ifr;
	int net_fd;
	int ret;

	net_fd = socket (PF_INET, SOCK_DGRAM, 0);
	if (net_fd == -1) {
		DBG("socket: %s\n", strerror (errno));
		return -1;
	}

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, params->tun_dev, sizeof(ifr.ifr_name) - 1);
	ret = ioctl(net_fd, SIOCGIFFLAGS, &ifr);
	if (ret == -1) {
		DBG("SIOCGIFFLAGS: %s\n", strerror (errno));
		close (net_fd);
		return -1;
	}

	ifr.ifr_flags |= IFF_UP;
	if (tun_mode == SSH_TUNMODE_POINTOPOINT)
		ifr.ifr_flags |= IFF_POINTOPOINT;

	ret = ioctl (net_fd, SIOCSIFFLAGS, &ifr);
	if (ret == -1) {
		DBG("SIOCSIFFLAGS: %s\n", strerror (errno));
		close (net_fd);
		return -1;
	}

	if (params->addr) {
		ret = read_addr (params->addr, &ifr.ifr_addr);
		if (ret < 0) {
			close (net_fd);
			return -1;
		}
		ret = ioctl (net_fd, SIOCSIFADDR, &ifr);
		if (ret == -1) {
			DBG("SIOCSIFADDR: %s\n", strerror (errno));
			close (net_fd);
			return -1;
		}
	}

	if (tun_mode == SSH_TUNMODE_POINTOPOINT && params->peer_addr) {
		ret = read_addr (params->peer_addr, &ifr.ifr_dstaddr);
		if (ret	< 0) {
			close (net_fd);
			return -1;
		}

		ret = ioctl (net_fd, SIOCSIFDSTADDR, &ifr);
		if (ret == -1) {
			DBG("SIOCSIFDSTADDR: %s\n", strerror (errno));
			close (net_fd);
			return -1;
		}
	}

	if (params->netmask) {
		ret = read_addr (params->netmask, &ifr.ifr_addr);
		if (ret < 0) {
			close (net_fd);
			return -1;
		}
		ret = ioctl (net_fd, SIOCSIFNETMASK, &ifr);
		if (ret == -1) {
			DBG("SIOCSIFNETMASK: %s\n", strerror (errno));
			close (net_fd);
			return -1;
		}
	}

	if (params->mtu) {
		long mtu;

		mtu = strtol (params->mtu, NULL, 10);
		if (mtu < 0 || mtu > 65535) {
			close (net_fd);
			return -1;
		}
		ret = ioctl (net_fd, SIOCSIFMTU, (void *)mtu);
		if (ret == -1) {
			DBG("SIOCSIFMTU: %s\n", strerror (errno));
			close (net_fd);
			return -1;
		}
	}
	close (net_fd);
	return 0;
}

int
sshtun_start (sshtun_handle_t handle)
{
	pid_t pid;
	uid_t tun_owner;
	struct passwd *pwd;
	int pr[2], pw[2];
	int ret;

	if (!handle)
		return -1;

	if (check_params (&handle->params) < 0)
		return -1;

	handle->tun_mode = !strcmp (handle->params.tun_mode, "pointopoint")
		? SSH_TUNMODE_POINTOPOINT : SSH_TUNMODE_ETHERNET;

	pwd = getpwnam (handle->params.tun_owner);
	if (!pwd) {
		DBG("getpwnam: %s\n", strerror (errno));
		return -1;
	}
	tun_owner = pwd->pw_uid;

	handle->params.tun_dev = create_tun (tun_owner, handle->tun_mode);
	if (!handle->params.tun_dev)
		return -1;

	if (pipe (pr) == -1 || pipe (pw) == -1) {
		DBG("pipe: %s\n", strerror (errno));
		sshtun_stop (handle);
		return -1;
	}

	pid = fork ();
	if (pid == -1) {
		DBG("fork: %s\n", strerror (errno));
		close (pr[0]);
		close (pr[1]);
		close (pw[0]);
		close (pw[1]);
		sshtun_stop (handle);
		return -1;
	}

	if (pid > 0) {
		struct sshtun_parent_st *parent = (struct sshtun_parent_st *)handle;

		close (pr[1]);
		close (pw[0]);

		handle->event_rfd.fd = pr[0];
		handle->event_wfd.fd = pw[1];

		ret = fcntl (handle->event_rfd.fd, F_SETFL, O_NONBLOCK);
		if (ret == -1) {
			DBG("fcntl: %s\n", strerror (errno));
			sshtun_stop (handle);
			return -1;
		}
		parent->pid = pid;

		return 0;
	} else {
		struct sshtun_child_st *child;

		close (pr[0]);
		close (pw[1]);

		setuid (tun_owner);

		child = malloc (sizeof *child);
		if (!child)
			return -1;
		init_child (child);
		memcpy (&child->common, handle,	sizeof child->common);

		child->common.event_rfd.fd = pw[0];
		child->common.event_wfd.fd = pr[1];

		ret = fcntl (child->common.event_rfd.fd, F_SETFL, O_NONBLOCK);
		if (ret == -1) {
			DBG("fcntl: %s\n", strerror (errno));
			goto child_error;
		}

		ret = start_child (child);
		if (ret < 0)
			goto child_error;

		stop_child (child);
		deinit_params (&child->common.params);
		free (child);
		exit (EXIT_SUCCESS);

	child_error:
		stop_child (child);
		deinit_params (&child->common.params);
		free (child);
		exit (EXIT_FAILURE);
	}
	return -1;
}

int
sshtun_stop (sshtun_handle_t handle)
{
	struct sshtun_parent_st *parent;

	if (!handle)
		return -1;

	stop_common (handle);		/* This will notify child a POLLHUP. */
	parent = (struct sshtun_parent_st *)handle;
	if (parent->pid > 0) {
		int status;

		/* kill (parent->pid, SIGTERM); */
		if (waitpid (parent->pid, &status, 0) == -1) {
			DBG("waitpid: %s\n", strerror (errno));
		}
		DBG("%d exited with %d\n", parent->pid, WEXITSTATUS(status));
		parent->pid = 0;
	}
	if (handle->params.tun_dev) {
		destroy_tun (handle->params.tun_dev, handle->tun_mode);
		free (handle->params.tun_dev);
		handle->params.tun_dev = NULL;
	}
	parent->state = SSHTUN_STATE_STOPPED;
	return 0;
}

int
sshtun_set_params (sshtun_handle_t handle, ...)
{
	sshtun_param_t param = 0;
	va_list ap;

	if (!handle)
		return -1;

	va_start (ap, handle);
	while (1) {
		if (!param) {
			param = va_arg (ap, sshtun_param_t);
			if (!param)
				break;
		} else {
			char *value;
			int ret;

			value = va_arg (ap, char *);
			ret = set_param (&handle->params, param, value, 0);
			if (ret < 0)
				return ret;
			param = 0;
		}
	}
	va_end (ap);

	return 0;
}

const char *
sshtun_get_param (sshtun_handle_t handle, sshtun_param_t param)
{
	int i;

	for (i = 0; i < NPARAMS; i++) {
		if (sshtun_param_defs[i].param == param) {
			char **address;

			address = (void *)&handle->params + sshtun_param_defs[i].offset;
			return *address;
		}
	}
	return NULL;
}

pid_t
sshtun_pid (sshtun_handle_t handle)
{
	if (!handle)
		return -1;
	return ((struct sshtun_parent_st *)handle)->pid;
}

sshtun_state_t
sshtun_state (sshtun_handle_t handle)
{
	if (!handle)
		return -1;
	return ((struct sshtun_parent_st *)handle)->state;
}

int
sshtun_event_fd (sshtun_handle_t handle)
{
	if (!handle)
		return -1;
	return handle->event_rfd.fd;
}

int
sshtun_dispatch_event (sshtun_handle_t handle)
{
	struct sshtun_parent_st *parent;
	char *event;
	int ret;

	if (!handle)
		return -1;

	parent = (struct sshtun_parent_st *)handle;
	event = recv_event (&handle->event_rfd);
	if (!event)
		return -1;

	if (!strncmp (event, "NEED_PASSWORD", 13))
		parent->state = SSHTUN_STATE_NEED_PASSWORD;
	else if (!strncmp (event, "BEGIN_CONFIG", 12))
		parent->state = SSHTUN_STATE_CONFIGURING;
	else if (!strncmp (event, "END_CONFIG", 10)) {
		ret = config_tun (&handle->params, handle->tun_mode);
		if (ret < 0) {
			sshtun_stop (handle);
			return -1;
		}
		parent->state = SSHTUN_STATE_CONFIGURED;
	} else if (parent->state == SSHTUN_STATE_CONFIGURING) {
		ret = add_config (&handle->params, event);
		if (ret < 0) {
			sshtun_stop (handle);
			return -1;
		}
	} else if (!strncmp (event, "START", 5))
		parent->state = SSHTUN_STATE_CONNECTED;

	return 0;
}

int
sshtun_send_event (sshtun_handle_t handle, const char *data)
{
	if (!handle)
		return -1;
	return send_event (&handle->event_wfd, data);
}
