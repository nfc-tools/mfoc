//-----------------------------------------------------------------------------
// Copyright (C) 2016, 2017 by piwi
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Implements a card only attack based on crypto text (encrypted nonces
// received during a nested authentication) only. Unlike other card only
// attacks this doesn't rely on implementation errors but only on the
// inherent weaknesses of the crypto1 cypher. Described in
//   Carlo Meijer, Roel Verdult, "Ciphertext-only Cryptanalysis on Hardened
//   Mifare Classic Cards" in Proceedings of the 22nd ACM SIGSAC Conference on 
//   Computer and Communications Security, 2015
//-----------------------------------------------------------------------------
//
// brute forcing is based on @aczids bitsliced brute forcer
// https://github.com/aczid/crypto1_bs with some modifications. Mainly:
// - don't rollback. Start with 2nd byte of nonce instead
// - reuse results of filter subfunctions
// - reuse results of previous nonces if some first bits are identical
// 
//-----------------------------------------------------------------------------
// aczid's Copyright notice:
//
// Bit-sliced Crypto-1 brute-forcing implementation
// Builds on the data structures returned by CraptEV1 craptev1_get_space(nonces, threshold, uid)
/*
Copyright (c) 2015-2016 Aram Verstegen

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
 */

#include <stdint.h>
#include "hardnested_bruteforce.h"   // statelist_t
#ifdef X86_SIMD
 // typedefs and declaration of functions:
typedef uint32_t* malloc_bitarray_t(uint32_t);
malloc_bitarray_t malloc_bitarray_dispatch;
malloc_bitarray_t malloc_bitarray_AVX512;
malloc_bitarray_t malloc_bitarray_AVX2;
malloc_bitarray_t malloc_bitarray_AVX;
malloc_bitarray_t malloc_bitarray_SSE2;

typedef void free_bitarray_t(uint32_t*);
free_bitarray_t free_bitarray_dispatch;
free_bitarray_t free_bitarray_AVX512;
free_bitarray_t free_bitarray_AVX2;
free_bitarray_t free_bitarray_AVX;
free_bitarray_t free_bitarray_SSE2;

typedef void bitarray_AND_t(uint32_t[], uint32_t[]);
bitarray_AND_t bitarray_AND_dispatch;
bitarray_AND_t bitarray_AND_AVX512;
bitarray_AND_t bitarray_AND_AVX2;
bitarray_AND_t bitarray_AND_AVX;
bitarray_AND_t bitarray_AND_SSE2;

typedef uint32_t count_bitarray_AND_t(uint32_t*, uint32_t*);
count_bitarray_AND_t count_bitarray_AND_dispatch;
count_bitarray_AND_t count_bitarray_AND_AVX512;
count_bitarray_AND_t count_bitarray_AND_AVX2;
count_bitarray_AND_t count_bitarray_AND_AVX;
count_bitarray_AND_t count_bitarray_AND_SSE2;

typedef uint32_t count_bitarray_low20_AND_t(uint32_t*, uint32_t*);
count_bitarray_low20_AND_t count_bitarray_low20_AND_dispatch;
count_bitarray_low20_AND_t count_bitarray_low20_AND_AVX512;
count_bitarray_low20_AND_t count_bitarray_low20_AND_AVX2;
count_bitarray_low20_AND_t count_bitarray_low20_AND_AVX;
count_bitarray_low20_AND_t count_bitarray_low20_AND_SSE2;

typedef void bitarray_AND4_t(uint32_t*, uint32_t*, uint32_t*, uint32_t*);
bitarray_AND4_t bitarray_AND4_dispatch;
bitarray_AND4_t bitarray_AND4_AVX512;
bitarray_AND4_t bitarray_AND4_AVX2;
bitarray_AND4_t bitarray_AND4_AVX;
bitarray_AND4_t bitarray_AND4_SSE2;

typedef void bitarray_OR_t(uint32_t[], uint32_t[]);
bitarray_OR_t bitarray_OR_dispatch;
bitarray_OR_t bitarray_OR_AVX512;
bitarray_OR_t bitarray_OR_AVX2;
bitarray_OR_t bitarray_OR_AVX;
bitarray_OR_t bitarray_OR_SSE2;

typedef uint32_t count_bitarray_AND2_t(uint32_t*, uint32_t*);
count_bitarray_AND2_t count_bitarray_AND2_dispatch;
count_bitarray_AND2_t count_bitarray_AND2_AVX512;
count_bitarray_AND2_t count_bitarray_AND2_AVX2;
count_bitarray_AND2_t count_bitarray_AND2_AVX;
count_bitarray_AND2_t count_bitarray_AND2_SSE2;

typedef uint32_t count_bitarray_AND3_t(uint32_t*, uint32_t*, uint32_t*);
count_bitarray_AND3_t count_bitarray_AND3_dispatch;
count_bitarray_AND3_t count_bitarray_AND3_AVX512;
count_bitarray_AND3_t count_bitarray_AND3_AVX2;
count_bitarray_AND3_t count_bitarray_AND3_AVX;
count_bitarray_AND3_t count_bitarray_AND3_SSE2;

typedef uint32_t count_bitarray_AND4_t(uint32_t*, uint32_t*, uint32_t*, uint32_t*);
count_bitarray_AND4_t count_bitarray_AND4_dispatch;
count_bitarray_AND4_t count_bitarray_AND4_AVX512;
count_bitarray_AND4_t count_bitarray_AND4_AVX2;
count_bitarray_AND4_t count_bitarray_AND4_AVX;
count_bitarray_AND4_t count_bitarray_AND4_SSE2;

typedef uint64_t crack_states_bitsliced_t(uint32_t, uint8_t*, statelist_t*, uint32_t*, uint64_t*, uint32_t, uint8_t*, noncelist_t*);
crack_states_bitsliced_t crack_states_bitsliced_dispatch;
crack_states_bitsliced_t crack_states_bitsliced_AVX512;
crack_states_bitsliced_t crack_states_bitsliced_AVX2;
crack_states_bitsliced_t crack_states_bitsliced_AVX;
crack_states_bitsliced_t crack_states_bitsliced_SSE2;

typedef void bitslice_test_nonces_t(uint32_t, uint32_t*, uint8_t*);
bitslice_test_nonces_t bitslice_test_nonces_dispatch;
bitslice_test_nonces_t bitslice_test_nonces_AVX512;
bitslice_test_nonces_t bitslice_test_nonces_AVX2;
bitslice_test_nonces_t bitslice_test_nonces_AVX;
bitslice_test_nonces_t bitslice_test_nonces_SSE2;

typedef enum instr {
    SIMD_NONE,
    SIMD_AVX512,
    SIMD_AVX2,
    SIMD_AVX,
    SIMD_SSE2,
} SIMDExecInstr;

extern SIMDExecInstr GetSIMDInstr(void);
#else

typedef uint32_t* malloc_bitarray_t(uint32_t);
malloc_bitarray_t malloc_bitarray_NOSIMD;

typedef void free_bitarray_t(uint32_t*);
free_bitarray_t free_bitarray_NOSIMD;

typedef void bitarray_AND_t(uint32_t[], uint32_t[]);
bitarray_AND_t bitarray_AND_NOSIMD;

typedef uint32_t count_bitarray_AND_t(uint32_t*, uint32_t*);
count_bitarray_AND_t count_bitarray_AND_NOSIMD;

typedef uint32_t count_bitarray_low20_AND_t(uint32_t*, uint32_t*);
count_bitarray_low20_AND_t count_bitarray_low20_AND_NOSIMD;

typedef void bitarray_AND4_t(uint32_t*, uint32_t*, uint32_t*, uint32_t*);
bitarray_AND4_t bitarray_AND4_NOSIMD;

typedef void bitarray_OR_t(uint32_t[], uint32_t[]);
bitarray_OR_t bitarray_OR_NOSIMD;

typedef uint32_t count_bitarray_AND2_t(uint32_t*, uint32_t*);
count_bitarray_AND2_t count_bitarray_AND2_NOSIMD;

typedef uint32_t count_bitarray_AND3_t(uint32_t*, uint32_t*, uint32_t*);
count_bitarray_AND3_t count_bitarray_AND3_NOSIMD;

typedef uint32_t count_bitarray_AND4_t(uint32_t*, uint32_t*, uint32_t*, uint32_t*);
count_bitarray_AND4_t count_bitarray_AND4_NOSIMD;

typedef uint64_t crack_states_bitsliced_t(uint32_t, uint8_t*, statelist_t*, uint32_t*, uint64_t*, uint32_t, uint8_t*, noncelist_t*);
crack_states_bitsliced_t crack_states_bitsliced_NOSIMD;

typedef void bitslice_test_nonces_t(uint32_t, uint32_t*, uint8_t*);
bitslice_test_nonces_t bitslice_test_nonces_NOSIMD;
#endif

extern uint32_t *malloc_bitarray(uint32_t x);
extern void free_bitarray(uint32_t *x);
extern void bitarray_AND(uint32_t *A, uint32_t *B);
extern uint32_t count_bitarray_AND(uint32_t *A, uint32_t *B);
extern uint32_t count_bitarray_low20_AND(uint32_t *A, uint32_t *B);
extern void bitarray_AND4(uint32_t *A, uint32_t *B, uint32_t *C, uint32_t *D);
extern void bitarray_OR(uint32_t *A, uint32_t *B);
extern uint32_t count_bitarray_AND2(uint32_t *A, uint32_t *B);
extern uint32_t count_bitarray_AND3(uint32_t *A, uint32_t *B, uint32_t *C);
extern uint32_t count_bitarray_AND4(uint32_t *A, uint32_t *B, uint32_t *C, uint32_t *D);
extern uint64_t crack_states_bitsliced(uint32_t cuid, uint8_t* best_first_bytes, statelist_t* p, uint32_t* keys_found, uint64_t* num_keys_tested, uint32_t nonces_to_bruteforce, uint8_t* bf_test_nonces_2nd_byte, noncelist_t* nonces);
extern void bitslice_test_nonces(uint32_t nonces_to_bruteforce, uint32_t* bf_test_nonces, uint8_t* bf_test_nonce_par);
