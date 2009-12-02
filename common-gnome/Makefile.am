noinst_LTLIBRARIES=libnm-sshtun-common-gnome.la

libnm_sshtun_common_gnome_la_CPPFLAGS = \
	$(NETWORK_MANAGER_CFLAGS) \
	$(GNOMEKEYRING_CFLAGS) \
	-DG_DISABLE_DEPRECATED

libnm_sshtun_common_gnome_la_SOURCES= \
	keyring-helpers.c \
	keyring-helpers.h

libnm_sshtun_common_gnome_la_LIBADD = \
	$(NETWORK_MANAGER_LIBS) \
	$(GNOMEKEYRING_LIBS)

