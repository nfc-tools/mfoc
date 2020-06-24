AM_CFLAGS  = @libnfc_CFLAGS@

bin_PROGRAMS = mfoc-hardnested

noinst_HEADERS = crapto1.h mfoc.h mifare.h nfc-utils.h parity.h hardnested/hardnested_bruteforce.h hardnested/tables.h hardnested/hardnested_cpu_dispatch.h cmdhfmfhard.h util.h util_posix.h ui.h bf_bench_data.h

mfoc_hardnested_SOURCES = crapto1.c crypto1.c mfoc.c mifare.c nfc-utils.c parity.c hardnested/hardnested_cpu_dispatch.c hardnested/hardnested_bruteforce.c hardnested/tables.c cmdhfmfhard.c util.c util_posix.c ui.c
mfoc_hardnested_LDADD   = @libnfc_LIBS@ $(SIMD)

dist_man_MANS = mfoc-hardnested.1

HARD_SWITCH_SSE2 = -mmmx -msse2 -mno-avx -mno-avx2 -mno-avx512f
HARD_SWITCH_AVX = -mmmx -msse2 -mavx -mno-avx2 -mno-avx512f
HARD_SWITCH_AVX2 = -mmmx -msse2 -mavx -mavx2 -mno-avx512f
HARD_SWITCH_AVX512 = -mmmx -msse2 -mavx -mavx2 -mavx512f

if X86_SIMD

  SIMD = hardnested/hardnested_bf_core_SSE2.o hardnested/hardnested_bf_core_AVX.o hardnested/hardnested_bf_core_AVX2.o hardnested/hardnested_bf_core_AVX512.o hardnested/hardnested_bitarray_core_SSE2.o hardnested/hardnested_bitarray_core_AVX.o hardnested/hardnested_bitarray_core_AVX2.o hardnested/hardnested_bitarray_core_AVX512.o
  
  hardnested/%_SSE2.o : hardnested/%_SSE2.c
	$(CC) $(DEPFLAGS) $(CFLAGS) $(HARD_SWITCH_SSE2) -c -o $@ $<

  hardnested/%_AVX.o : hardnested/%_AVX.c
	$(CC) $(DEPFLAGS) $(CFLAGS) $(HARD_SWITCH_AVX) -c -o $@ $<

  hardnested/%_AVX2.o : hardnested/%_AVX2.c
	$(CC) $(DEPFLAGS) $(CFLAGS) $(HARD_SWITCH_AVX2) -c -o $@ $<

  hardnested/%_AVX512.o : hardnested/%_AVX512.c
	$(CC) $(DEPFLAGS) $(CFLAGS) $(HARD_SWITCH_AVX512) -c -o $@ $<

else

  SIMDOBJ = hardnested/hardnested_bf_core_NOSIMD.o hardnested/hardnested_bitarray_core_NOSIMD.o
  hardnested/%_NOSIMD.o : hardnested/%.c
	$(CC) $(DEPFLAGS) $(CFLAGS) -c -o $@ $<

endif
