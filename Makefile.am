AM_CPPFLAGS = $(GPGME_CFLAGS) -I$(prefix)/include/libmilter
AM_LDFLAGS = -pthread
LDADD = $(GPGME_LIBS) -lmilter 


bin_PROGRAMS = pgpmilter
pgpmilter_SOURCES = main.c


