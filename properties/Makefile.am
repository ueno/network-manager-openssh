plugindir = $(libdir)/NetworkManager
plugin_LTLIBRARIES = libnm-openssh-properties.la

libnm_openssh_properties_la_SOURCES = \
	nm-openssh.c \
	nm-openssh.h

gladedir = $(datadir)/gnome-vpn-properties/openssh
glade_DATA = nm-openssh-dialog.glade

libnm_openssh_properties_la_CFLAGS =                    \
        $(GLADE_CFLAGS)                                 \
        $(GTK_CFLAGS)                                   \
        $(GCONF_CFLAGS)                                 \
        $(NETWORK_MANAGER_CFLAGS)                       \
        $(GNOMEKEYRING_CFLAGS)                          \
        $(DISABLE_DEPRECATED)                           \
        -I$(top_srcdir)/                                \
        -DICONDIR=\""$(datadir)/pixmaps"\"              \
        -DGLADEDIR=\""$(gladedir)"\"                    \
        -DG_DISABLE_DEPRECATED                          \
        -DGDK_DISABLE_DEPRECATED                        \
        -DGNOME_DISABLE_DEPRECATED                      \
        -DGNOMELOCALEDIR=\"$(datadir)/locale\"          \
        -DVERSION=\"$(VERSION)\"

libnm_openssh_properties_la_LIBADD =					\
        $(GLADE_LIBS)							\
        $(GTK_LIBS)							\
        $(GCONF_LIBS)							\
        $(NETWORK_MANAGER_LIBS)						\
	$(top_builddir)/common-gnome/libnm-openssh-common-gnome.la

libnm_openssh_properties_la_LDFLAGS =   \
        -avoid-version

CLEANFILES = *.bak *.gladep *~

EXTRA_DIST =                            \
        $(glade_DATA)
