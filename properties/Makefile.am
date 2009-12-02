plugindir = $(libdir)/NetworkManager
plugin_LTLIBRARIES = libnm-sshtun-properties.la

libnm_sshtun_properties_la_SOURCES = \
	nm-sshtun.c \
	nm-sshtun.h

gladedir = $(datadir)/gnome-vpn-properties/sshtun
glade_DATA = nm-sshtun-dialog.glade

libnm_sshtun_properties_la_CFLAGS =                    \
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

libnm_sshtun_properties_la_LIBADD =    \
        $(GLADE_LIBS)                   \
        $(GTK_LIBS)                     \
        $(GCONF_LIBS)                   \
        $(NETWORK_MANAGER_LIBS)

libnm_sshtun_properties_la_LDFLAGS =   \
        -avoid-version

CLEANFILES = *.bak *.gladep *~

EXTRA_DIST =                            \
        $(glade_DATA)
