libexec_PROGRAMS = nm-openssh-auth-dialog

nm_openssh_auth_dialog_CPPFLAGS =			\
	$(GTHREAD_CFLAGS)			\
	$(GTK_CFLAGS)				\
	$(GCONF_CFLAGS)				\
	$(NETWORK_MANAGER_CFLAGS)		\
	$(GNOMEKEYRING_CFLAGS) \
	-I$(top_srcdir)/
	-DICONDIR=\""$(datadir)/pixmaps"\"	\
	-DGLADEDIR=\""$(gladedir)"\"		\
	-DBINDIR=\""$(bindir)"\"		\
	-DG_DISABLE_DEPRECATED			\
	-DGDK_DISABLE_DEPRECATED		\
	-DGNOME_DISABLE_DEPRECATED		\
	-DGNOMELOCALEDIR=\"$(datadir)/locale\"	\
	-DVERSION=\"$(VERSION)\"

nm_openssh_auth_dialog_SOURCES =			\
	main.c					\
	gnome-two-password-dialog.c		\
	gnome-two-password-dialog.h

nm_openssh_auth_dialog_LDADD =			\
	$(GTK_LIBS)				\
	$(GCONF_LIBS)				\
	$(top_builddir)/common-gnome/libnm-openssh-common-gnome.la

CLEANFILES = *~
