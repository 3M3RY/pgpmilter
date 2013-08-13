AM_CPPFLAGS = $(GPGME_CFLAGS) -I$(prefix)/include/libmilter
AM_LDFLAGS = -pthread
LDADD = $(GPGME_LIBS) -lmilter 


bin_PROGRAMS = pgp_milter
pgp_milter_SOURCES = main.c


