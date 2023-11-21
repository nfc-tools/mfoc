AM_CFLAGS  = @libnfc_CFLAGS@

bin_PROGRAMS = mfoc

noinst_HEADERS = crapto1.h mfoc.h mifare.h nfc-utils.h parity.h

mfoc_SOURCES = crapto1.c crypto1.c mfoc.c mifare.c nfc-utils.c parity.c
mfoc_LDADD   = @libnfc_LIBS@

dist_man_MANS = mfoc.1
