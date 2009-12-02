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

libexec_PROGRAMS = nm-sshtun-service

nm_sshtun_service_SOURCES =				\
				nm-sshtun-service.c	\
				nm-sshtun-service.h	\
				sshtun.c		\
				sshtun.h


nm_sshtun_service_LDADD = $(NETWORK_MANAGER_LIBS) $(LIBSSH2_LIBS)

CLEANFILES = *~
