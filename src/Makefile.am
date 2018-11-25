AM_CFLAGS  = @libnfc_CFLAGS@

bin_PROGRAMS = mfoc

noinst_HEADERS = crapto1.h mfoc.h mifare.h nfc-utils.h parity.h hardnested/hardnested_bruteforce.h hardnested/tables.h cmdhfmfhard.h util.h util_posix.h ui.h

mfoc_SOURCES = crapto1.c crypto1.c mfoc.c mifare.c nfc-utils.c parity.c hardnested/hardnested_bruteforce.c hardnested/tables.c cmdhfmfhard.c util.c util_posix.c ui.c
mfoc_LDADD   = @libnfc_LIBS@ $(MULTIARCHOBJS)

dist_man_MANS = mfoc.1


#MULTIARCH = hardnested/hardnested_bf_core.c hardnested/hardnested_bitarray_core.c

MULTIARCHOBJS = hardnested/hardnested_bf_core_NOSIMD.o \
		hardnested/hardnested_bf_core_MMX.o \
		hardnested/hardnested_bf_core_SSE2.o \
		hardnested/hardnested_bf_core_AVX.o \
		hardnested/hardnested_bf_core_AVX2.o \
		hardnested/hardnested_bf_core_AVX512.o \
		hardnested/hardnested_bitarray_core_NOSIMD.o \
		hardnested/hardnested_bitarray_core_MMX.o \
		hardnested/hardnested_bitarray_core_SSE2.o \
		hardnested/hardnested_bitarray_core_AVX.o \
		hardnested/hardnested_bitarray_core_AVX2.o \
		hardnested/hardnested_bitarray_core_AVX512.o

HARD_SWITCH_NOSIMD = -mno-mmx -mno-sse2 -mno-avx -mno-avx2 -mno-avx512f
HARD_SWITCH_MMX = -mmmx -mno-sse2 -mno-avx -mno-avx2 -mno-avx512f
HARD_SWITCH_SSE2 = -mmmx -msse2 -mno-avx -mno-avx2 -mno-avx512f
HARD_SWITCH_AVX = -mmmx -msse2 -mavx -mno-avx2 -mno-avx512f
HARD_SWITCH_AVX2 = -mmmx -msse2 -mavx -mavx2 -mno-avx512f
HARD_SWITCH_AVX512 = -mmmx -msse2 -mavx -mavx2 -mavx512f

hardnested/%_NOSIMD.o : hardnested/%.c
	$(CC) $(DEPFLAGS) $(CFLAGS) $(HARD_SWITCH_NOSIMD) -c -o $@ $<

hardnested/%_MMX.o : hardnested/%.c
	$(CC) $(DEPFLAGS) $(CFLAGS) $(HARD_SWITCH_MMX) -c -o $@ $<

hardnested/%_SSE2.o : hardnested/%.c
	$(CC) $(DEPFLAGS) $(CFLAGS) $(HARD_SWITCH_SSE2) -c -o $@ $<

hardnested/%_AVX.o : hardnested/%.c
	$(CC) $(DEPFLAGS) $(CFLAGS) $(HARD_SWITCH_AVX) -c -o $@ $<

hardnested/%_AVX2.o : hardnested/%.c
	$(CC) $(DEPFLAGS) $(CFLAGS) $(HARD_SWITCH_AVX2) -c -o $@ $<

hardnested/%_AVX512.o : hardnested/%.c
	$(CC) $(DEPFLAGS) $(CFLAGS) $(HARD_SWITCH_AVX512) -c -o $@ $<
