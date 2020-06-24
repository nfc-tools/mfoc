//-----------------------------------------------------------------------------
// Copyright (C) 2016, 2017 by piwi
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.ch b
//-----------------------------------------------------------------------------
// Implements a card only attack based on crypto text (encrypted nonces
// received during a nested authentication) only. Unlike other card only
// attacks this doesn't rely on implementation errors but only on the
// inherent weaknesses of the crypto1 cypher. Described in
//   Carlo Meijer, Roel Verdult, "Ciphertext-only Cryptanalysis on Hardened
//   Mifare Classic Cards" in Proceedings of the 22nd ACM SIGSAC Conference on
//   Computer and Communications Security, 2015
//-----------------------------------------------------------------------------
// some helper functions which can benefit from SIMD instructions or other special instructions
//

#include "hardnested_cpu_dispatch.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef _MSC_VER
#include <intrin.h>
#endif

#ifdef X86_SIMD
// pointers to functions:
malloc_bitarray_t* malloc_bitarray_function_p = &malloc_bitarray_dispatch;
free_bitarray_t* free_bitarray_function_p = &free_bitarray_dispatch;
bitarray_AND_t* bitarray_AND_function_p = &bitarray_AND_dispatch;
count_bitarray_AND_t* count_bitarray_AND_function_p = &count_bitarray_AND_dispatch;
count_bitarray_low20_AND_t* count_bitarray_low20_AND_function_p = &count_bitarray_low20_AND_dispatch;
bitarray_AND4_t* bitarray_AND4_function_p = &bitarray_AND4_dispatch;
bitarray_OR_t* bitarray_OR_function_p = &bitarray_OR_dispatch;
count_bitarray_AND2_t* count_bitarray_AND2_function_p = &count_bitarray_AND2_dispatch;
count_bitarray_AND3_t* count_bitarray_AND3_function_p = &count_bitarray_AND3_dispatch;
count_bitarray_AND4_t* count_bitarray_AND4_function_p = &count_bitarray_AND4_dispatch;

crack_states_bitsliced_t* crack_states_bitsliced_function_p = &crack_states_bitsliced_dispatch;
bitslice_test_nonces_t* bitslice_test_nonces_function_p = &bitslice_test_nonces_dispatch;

SIMDExecInstr GetSIMDInstr() {
    SIMDExecInstr instr = SIMD_NONE;
#ifdef _MSC_VER
    int cpuid[4];
    __cpuid(cpuid, 1);
    if (cpuid[1] >> 16 & 1) instr = SIMD_AVX512;
    else if (cpuid[1] >> 5 & 1) instr = SIMD_AVX2;
    else if (cpuid[2] >> 28 & 1) instr = SIMD_AVX;
    else if (cpuid[3] >> 26 & 1) instr = SIMD_SSE2;
#else
    if (__builtin_cpu_supports("avx512f")) instr = SIMD_AVX512;
    else if (__builtin_cpu_supports("avx2")) instr = SIMD_AVX2;
    else if (__builtin_cpu_supports("avx")) instr = SIMD_AVX;
    else if (__builtin_cpu_supports("sse2")) instr = SIMD_SSE2;
#endif
    return instr;
}

static void NoCpu() {
    printf("\nThis program requires at least an SSE2 capable CPU. Exiting...\n");
    exit(4);
}

// determine the available instruction set at runtime and call the correct function

uint32_t* malloc_bitarray_dispatch(uint32_t x) {
    switch (GetSIMDInstr()) {
    case SIMD_AVX512:
        malloc_bitarray_function_p = &malloc_bitarray_AVX512;
        break;
    case SIMD_AVX2:
        malloc_bitarray_function_p = &malloc_bitarray_AVX2;
        break;
    case SIMD_AVX:
        malloc_bitarray_function_p = &malloc_bitarray_AVX;
        break;
    case SIMD_SSE2:
        malloc_bitarray_function_p = &malloc_bitarray_SSE2;
        break;
    default:
        NoCpu();
    }

    // call the most optimized function for this CPU
    return (*malloc_bitarray_function_p)(x);
}

void free_bitarray_dispatch(uint32_t* x) {
    switch (GetSIMDInstr()) {
    case SIMD_AVX512:
        free_bitarray_function_p = &free_bitarray_AVX512;
        break;
    case SIMD_AVX2:
        free_bitarray_function_p = &free_bitarray_AVX2;
        break;
    case SIMD_AVX:
        free_bitarray_function_p = &free_bitarray_AVX;
        break;
    case SIMD_SSE2:
        free_bitarray_function_p = &free_bitarray_SSE2;
        break;
    default:
        NoCpu();
    }

    // call the most optimized function for this CPU
    (*free_bitarray_function_p)(x);
}

void bitarray_AND_dispatch(uint32_t* A, uint32_t* B) {
    switch (GetSIMDInstr()) {
    case SIMD_AVX512:
        bitarray_AND_function_p = &bitarray_AND_AVX512;
        break;
    case SIMD_AVX2:
        bitarray_AND_function_p = &bitarray_AND_AVX2;
        break;
    case SIMD_AVX:
        bitarray_AND_function_p = &bitarray_AND_AVX;
        break;
    case SIMD_SSE2:
        bitarray_AND_function_p = &bitarray_AND_SSE2;
        break;
    default:
        NoCpu();
    }

    // call the most optimized function for this CPU
    (*bitarray_AND_function_p)(A, B);
}

uint32_t count_bitarray_AND_dispatch(uint32_t* A, uint32_t* B) {
    switch (GetSIMDInstr()) {
    case SIMD_AVX512:
        count_bitarray_AND_function_p = &count_bitarray_AND_AVX512;
        break;
    case SIMD_AVX2:
        count_bitarray_AND_function_p = &count_bitarray_AND_AVX2;
        break;
    case SIMD_AVX:
        count_bitarray_AND_function_p = &count_bitarray_AND_AVX;
        break;
    case SIMD_SSE2:
        count_bitarray_AND_function_p = &count_bitarray_AND_SSE2;
        break;
    default:
        NoCpu();
    }

    // call the most optimized function for this CPU
    return (*count_bitarray_AND_function_p)(A, B);
}

uint32_t count_bitarray_low20_AND_dispatch(uint32_t* A, uint32_t* B) {
    switch (GetSIMDInstr()) {
    case SIMD_AVX512:
        count_bitarray_low20_AND_function_p = &count_bitarray_low20_AND_AVX512;
        break;
    case SIMD_AVX2:
        count_bitarray_low20_AND_function_p = &count_bitarray_low20_AND_AVX2;
        break;
    case SIMD_AVX:
        count_bitarray_low20_AND_function_p = &count_bitarray_low20_AND_AVX;
        break;
    case SIMD_SSE2:
        count_bitarray_low20_AND_function_p = &count_bitarray_low20_AND_SSE2;
        break;
    default:
        NoCpu();
    }

    // call the most optimized function for this CPU
    return (*count_bitarray_low20_AND_function_p)(A, B);
}

void bitarray_AND4_dispatch(uint32_t* A, uint32_t* B, uint32_t* C, uint32_t* D) {
    switch (GetSIMDInstr()) {
    case SIMD_AVX512:
        bitarray_AND4_function_p = &bitarray_AND4_AVX512;
        break;
    case SIMD_AVX2:
        bitarray_AND4_function_p = &bitarray_AND4_AVX2;
        break;
    case SIMD_AVX:
        bitarray_AND4_function_p = &bitarray_AND4_AVX;
        break;
    case SIMD_SSE2:
        bitarray_AND4_function_p = &bitarray_AND4_SSE2;
        break;
    default:
        NoCpu();
    }

    // call the most optimized function for this CPU
    (*bitarray_AND4_function_p)(A, B, C, D);
}

void bitarray_OR_dispatch(uint32_t* A, uint32_t* B) {
    switch (GetSIMDInstr()) {
    case SIMD_AVX512:
        bitarray_OR_function_p = &bitarray_OR_AVX512;
        break;
    case SIMD_AVX2:
        bitarray_OR_function_p = &bitarray_OR_AVX2;
        break;
    case SIMD_AVX:
        bitarray_OR_function_p = &bitarray_OR_AVX;
        break;
    case SIMD_SSE2:
        bitarray_OR_function_p = &bitarray_OR_SSE2;
        break;
    default:
        NoCpu();
    }

    // call the most optimized function for this CPU
    (*bitarray_OR_function_p)(A, B);
}

uint32_t count_bitarray_AND2_dispatch(uint32_t* A, uint32_t* B) {
    switch (GetSIMDInstr()) {
    case SIMD_AVX512:
        count_bitarray_AND2_function_p = &count_bitarray_AND2_AVX512;
        break;
    case SIMD_AVX2:
        count_bitarray_AND2_function_p = &count_bitarray_AND2_AVX2;
        break;
    case SIMD_AVX:
        count_bitarray_AND2_function_p = &count_bitarray_AND2_AVX;
        break;
    case SIMD_SSE2:
        count_bitarray_AND2_function_p = &count_bitarray_AND2_SSE2;
        break;
    default:
        NoCpu();
    }

    // call the most optimized function for this CPU
    return (*count_bitarray_AND2_function_p)(A, B);
}

uint32_t count_bitarray_AND3_dispatch(uint32_t* A, uint32_t* B, uint32_t* C) {
    switch (GetSIMDInstr()) {
    case SIMD_AVX512:
        count_bitarray_AND3_function_p = &count_bitarray_AND3_AVX512;
        break;
    case SIMD_AVX2:
        count_bitarray_AND3_function_p = &count_bitarray_AND3_AVX2;
        break;
    case SIMD_AVX:
        count_bitarray_AND3_function_p = &count_bitarray_AND3_AVX;
        break;
    case SIMD_SSE2:
        count_bitarray_AND3_function_p = &count_bitarray_AND3_SSE2;
        break;
    default:
        NoCpu();
    }

    // call the most optimized function for this CPU
    return (*count_bitarray_AND3_function_p)(A, B, C);
}

uint32_t count_bitarray_AND4_dispatch(uint32_t* A, uint32_t* B, uint32_t* C, uint32_t* D) {
    switch (GetSIMDInstr()) {
    case SIMD_AVX512:
        count_bitarray_AND4_function_p = &count_bitarray_AND4_AVX512;
        break;
    case SIMD_AVX2:
        count_bitarray_AND4_function_p = &count_bitarray_AND4_AVX2;
        break;
    case SIMD_AVX:
        count_bitarray_AND4_function_p = &count_bitarray_AND4_AVX;
        break;
    case SIMD_SSE2:
        count_bitarray_AND4_function_p = &count_bitarray_AND4_SSE2;
        break;
    default:
        NoCpu();
    }

    // call the most optimized function for this CPU
    return (*count_bitarray_AND4_function_p)(A, B, C, D);
}

uint64_t crack_states_bitsliced_dispatch(uint32_t cuid, uint8_t* best_first_bytes, statelist_t* p, uint32_t* keys_found, uint64_t* num_keys_tested, uint32_t nonces_to_bruteforce, uint8_t* bf_test_nonce_2nd_byte, noncelist_t* nonces) {
    switch (GetSIMDInstr()) {
    case SIMD_AVX512:
        crack_states_bitsliced_function_p = &crack_states_bitsliced_AVX512;
        break;
    case SIMD_AVX2:
        crack_states_bitsliced_function_p = &crack_states_bitsliced_AVX2;
        break;
    case SIMD_AVX:
        crack_states_bitsliced_function_p = &crack_states_bitsliced_AVX;
        break;
    case SIMD_SSE2:
        crack_states_bitsliced_function_p = &crack_states_bitsliced_SSE2;
        break;
    default:
        NoCpu();
    }

    // call the most optimized function for this CPU
    return (*crack_states_bitsliced_function_p)(cuid, best_first_bytes, p, keys_found, num_keys_tested, nonces_to_bruteforce, bf_test_nonce_2nd_byte, nonces);
}

void bitslice_test_nonces_dispatch(uint32_t nonces_to_bruteforce, uint32_t* bf_test_nonce, uint8_t* bf_test_nonce_par) {
    switch (GetSIMDInstr()) {
    case SIMD_AVX512:
        bitslice_test_nonces_function_p = &bitslice_test_nonces_AVX512;
        break;
    case SIMD_AVX2:
        bitslice_test_nonces_function_p = &bitslice_test_nonces_AVX2;
        break;
    case SIMD_AVX:
        bitslice_test_nonces_function_p = &bitslice_test_nonces_AVX;
        break;
    case SIMD_SSE2:
        bitslice_test_nonces_function_p = &bitslice_test_nonces_SSE2;
        break;
    default:
        NoCpu();
    }

    // call the most optimized function for this CPU
    (*bitslice_test_nonces_function_p)(nonces_to_bruteforce, bf_test_nonce, bf_test_nonce_par);
}
#else

malloc_bitarray_t* malloc_bitarray_function_p = &malloc_bitarray_NOSIMD;
free_bitarray_t* free_bitarray_function_p = &free_bitarray_NOSIMD;
bitarray_AND_t* bitarray_AND_function_p = &bitarray_AND_NOSIMD;
count_bitarray_AND_t* count_bitarray_AND_function_p = &count_bitarray_AND_NOSIMD;
count_bitarray_low20_AND_t* count_bitarray_low20_AND_function_p = &count_bitarray_low20_AND_NOSIMD;
bitarray_AND4_t* bitarray_AND4_function_p = &bitarray_AND4_NOSIMD;
bitarray_OR_t* bitarray_OR_function_p = &bitarray_OR_NOSIMD;
count_bitarray_AND2_t* count_bitarray_AND2_function_p = &count_bitarray_AND2_NOSIMD;
count_bitarray_AND3_t* count_bitarray_AND3_function_p = &count_bitarray_AND3_NOSIMD;
count_bitarray_AND4_t* count_bitarray_AND4_function_p = &count_bitarray_AND4_NOSIMD;

crack_states_bitsliced_t* crack_states_bitsliced_function_p = &crack_states_bitsliced_NOSIMD;
bitslice_test_nonces_t* bitslice_test_nonces_function_p = &bitslice_test_nonces_NOSIMD;
#endif
/////////////////////////////////////////////////
// Entries to dispatched function calls

inline uint32_t* malloc_bitarray(uint32_t x) {
    return (*malloc_bitarray_function_p)(x);
}

inline void free_bitarray(uint32_t* x) {
    (*free_bitarray_function_p)(x);
}

inline void bitarray_AND(uint32_t* A, uint32_t* B) {
    (*bitarray_AND_function_p)(A, B);
}

inline uint32_t count_bitarray_AND(uint32_t* A, uint32_t* B) {
    return (*count_bitarray_AND_function_p)(A, B);
}

inline uint32_t count_bitarray_low20_AND(uint32_t* A, uint32_t* B) {
    return (*count_bitarray_low20_AND_function_p)(A, B);
}

inline void bitarray_AND4(uint32_t* A, uint32_t* B, uint32_t* C, uint32_t* D) {
    (*bitarray_AND4_function_p)(A, B, C, D);
}

inline void bitarray_OR(uint32_t* A, uint32_t* B) {
    (*bitarray_OR_function_p)(A, B);
}

inline uint32_t count_bitarray_AND2(uint32_t* A, uint32_t* B) {
    return (*count_bitarray_AND2_function_p)(A, B);
}

inline uint32_t count_bitarray_AND3(uint32_t* A, uint32_t* B, uint32_t* C) {
    return (*count_bitarray_AND3_function_p)(A, B, C);
}

inline uint32_t count_bitarray_AND4(uint32_t* A, uint32_t* B, uint32_t* C, uint32_t* D) {
    return (*count_bitarray_AND4_function_p)(A, B, C, D);
}

uint64_t crack_states_bitsliced(uint32_t cuid, uint8_t* best_first_bytes, statelist_t* p, uint32_t* keys_found, uint64_t* num_keys_tested, uint32_t nonces_to_bruteforce, uint8_t* bf_test_nonce_2nd_byte, noncelist_t* nonces) {
    return (*crack_states_bitsliced_function_p)(cuid, best_first_bytes, p, keys_found, num_keys_tested, nonces_to_bruteforce, bf_test_nonce_2nd_byte, nonces);
}

void bitslice_test_nonces(uint32_t nonces_to_bruteforce, uint32_t* bf_test_nonce, uint8_t* bf_test_nonce_par) {
    (*bitslice_test_nonces_function_p)(nonces_to_bruteforce, bf_test_nonce, bf_test_nonce_par);
}
