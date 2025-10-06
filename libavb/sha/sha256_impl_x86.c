/*
 * Copyright (C) 2025 The Android Open Source Project
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../avb_sha.h"
#include "avb_crypto_ops_impl.h"

const uint32_t sha256_seq[8] = {3, 2, 7, 6, 1, 0, 5, 4};

typedef int vb2_m128i __attribute__ ((vector_size(16)));

static inline vb2_m128i vb2_loadu_si128(vb2_m128i *ptr)
{
    vb2_m128i result;
    asm volatile ("movups %1, %0" : "=x"(result) : "m"(*ptr));
    return result;
}

static inline void vb2_storeu_si128(vb2_m128i *to, vb2_m128i from)
{
    asm volatile ("movups %1, %0" : "=m"(*to) : "x"(from));
}

static inline vb2_m128i vb2_add_epi32(vb2_m128i a, vb2_m128i b)
{
    return a + b;
}

static inline vb2_m128i vb2_shuffle_epi8(vb2_m128i value, vb2_m128i mask)
{
    asm ("pshufb %1, %0" : "+x"(value) : "xm"(mask));
    return value;
}

static inline vb2_m128i vb2_shuffle_epi32(vb2_m128i value, int mask)
{
    vb2_m128i result;
    asm ("pshufd %2, %1, %0" : "=x"(result) : "xm"(value), "i" (mask));
    return result;
}

static inline vb2_m128i vb2_alignr_epi8(vb2_m128i a, vb2_m128i b, int imm8)
{
    asm ("palignr %2, %1, %0" : "+x"(a) : "xm"(b), "i"(imm8));
    return a;
}

static inline vb2_m128i vb2_sha256msg1_epu32(vb2_m128i a, vb2_m128i b)
{
    asm ("sha256msg1 %1, %0" : "+x"(a) : "xm"(b));
    return a;
}

static inline vb2_m128i vb2_sha256msg2_epu32(vb2_m128i a, vb2_m128i b)
{
    asm ("sha256msg2 %1, %0" : "+x"(a) : "xm"(b));
    return a;
}

static inline vb2_m128i vb2_sha256rnds2_epu32(vb2_m128i a, vb2_m128i b,
                                              vb2_m128i k)
{
    asm ("sha256rnds2 %1, %0" : "+x"(a) : "xm"(b), "Yz"(k));
    return a;
}

#define SHA256_X86_PUT_STATE1(j, i)                                         \
    {                                                                       \
        msgtmp[j] = vb2_loadu_si128((vb2_m128i *)                            \
                (message + (i << 6) + (j * 16)));                           \
        msgtmp[j] = vb2_shuffle_epi8(msgtmp[j], shuf_mask);                 \
        msg = vb2_add_epi32(msgtmp[j],                                      \
            vb2_loadu_si128((vb2_m128i *)&sha256_k[j * 4]));                \
        state1 = vb2_sha256rnds2_epu32(state1, state0, msg);                \
    }

#define SHA256_X86_PUT_STATE0()                                             \
    {                                                                       \
        msg    = vb2_shuffle_epi32(msg, 0x0E);                              \
        state0 = vb2_sha256rnds2_epu32(state0, state1, msg);                \
    }

#define SHA256_X86_LOOP(j)                                                  \
    {                                                                       \
        int k = j & 3;                                                      \
        int prev_k = (k + 3) & 3;                                           \
        int next_k = (k + 1) & 3;                                           \
        msg = vb2_add_epi32(msgtmp[k],                                      \
            vb2_loadu_si128((vb2_m128i *)&sha256_k[j * 4]));                \
        state1 = vb2_sha256rnds2_epu32(state1, state0, msg);                \
        tmp = vb2_alignr_epi8(msgtmp[k], msgtmp[prev_k], 4);                \
        msgtmp[next_k] = vb2_add_epi32(msgtmp[next_k], tmp);                \
        msgtmp[next_k] = vb2_sha256msg2_epu32(msgtmp[next_k],               \
                    msgtmp[k]);                                             \
        SHA256_X86_PUT_STATE0();                                            \
        msgtmp[prev_k] = vb2_sha256msg1_epu32(msgtmp[prev_k],               \
                msgtmp[k]);                                                 \
    }

void SHA256_transform(AvbSHA256ImplCtx* ctx, const uint8_t* message, size_t block_nb)
{
  vb2_m128i state0, state1, msg, abef_save, cdgh_save;
  vb2_m128i msgtmp[4];
  vb2_m128i tmp;
  const vb2_m128i shuf_mask = {0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f};

  state0 = vb2_loadu_si128((vb2_m128i *)&ctx->h[0]);
  state1 = vb2_loadu_si128((vb2_m128i *)&ctx->h[4]);
  for (int i = 0; i < (int) block_nb; i++) {
    abef_save = state0;
    cdgh_save = state1;

    SHA256_X86_PUT_STATE1(0, i);
    SHA256_X86_PUT_STATE0();

    SHA256_X86_PUT_STATE1(1, i);
    SHA256_X86_PUT_STATE0();
    msgtmp[0] = vb2_sha256msg1_epu32(msgtmp[0], msgtmp[1]);

    SHA256_X86_PUT_STATE1(2, i);
    SHA256_X86_PUT_STATE0();
    msgtmp[1] = vb2_sha256msg1_epu32(msgtmp[1], msgtmp[2]);

    SHA256_X86_PUT_STATE1(3, i);
    tmp = vb2_alignr_epi8(msgtmp[3], msgtmp[2], 4);
    msgtmp[0] = vb2_add_epi32(msgtmp[0], tmp);
    msgtmp[0] = vb2_sha256msg2_epu32(msgtmp[0], msgtmp[3]);
    SHA256_X86_PUT_STATE0();
    msgtmp[2] = vb2_sha256msg1_epu32(msgtmp[2], msgtmp[3]);

    SHA256_X86_LOOP(4);
    SHA256_X86_LOOP(5);
    SHA256_X86_LOOP(6);
    SHA256_X86_LOOP(7);
    SHA256_X86_LOOP(8);
    SHA256_X86_LOOP(9);
    SHA256_X86_LOOP(10);
    SHA256_X86_LOOP(11);
    SHA256_X86_LOOP(12);
    SHA256_X86_LOOP(13);
    SHA256_X86_LOOP(14);

    msg = vb2_add_epi32(msgtmp[3],
    vb2_loadu_si128((vb2_m128i *)&sha256_k[15 * 4]));
    state1 = vb2_sha256rnds2_epu32(state1, state0, msg);
            SHA256_X86_PUT_STATE0();

    state0 = vb2_add_epi32(state0, abef_save);
    state1 = vb2_add_epi32(state1, cdgh_save);
  }

  vb2_storeu_si128((vb2_m128i *)&ctx->h[0], state0);
  vb2_storeu_si128((vb2_m128i *)&ctx->h[4], state1);
}
