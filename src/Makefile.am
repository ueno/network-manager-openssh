AM_CPPFLAGS =					\
	$(DBUS_CFLAGS)				\
	$(NETWORK_MANAGER_CFLAGS)		\
	$(LIBSSH2_CFLAGS)			\
	-DG_DISABLE_DEPRECATED			\
	-DBINDIR=\"$(bindir)\"			\
	-DPREFIX=\""$(prefix)"\"		\
	-DSYSCONFDIR=\""$(sysconfdir)"\"	\
	-DVERSION="\"$(VERSION)\""		\
	-DLIBDIR=\""$(libdir)"\"		\
	-DLIBEXECDIR=\""$(libexecdir)"\"	\
	-DLOCALSTATEDIR=\""$(localstatedir)"\"	\
	-DDATADIR=\"$(datadir)\"

libexec_PROGRAMS = nm-openssh-service

nm_openssh_service_SOURCES =				\
				nm-openssh-service.c	\
				nm-openssh-service.h	\
				sshtun.c		\
				sshtun.h


nm_openssh_service_LDADD = $(NETWORK_MANAGER_LIBS) $(LIBSSH2_LIBS)

CLEANFILES = *~
