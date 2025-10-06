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

const uint32_t sha256_seq[8] = {0, 1, 2, 3, 4, 5, 6, 7};

/*
 * Performs the core SHA-256 transform on one or more blocks using
 * ARM Crypto Extensions.
 */

/* Helper for generating an ADD instruction only if the register is specified */
#define ADD_IF_NOT_EMPTY(VREG_DEST, VREG_SRC1, VREG_SRC2) \
    "add        v" #VREG_DEST ".4s, v" #VREG_SRC1 ".4s, v" #VREG_SRC2 ".4s\n\t"

/*
 * Macro replicating the 'add_only' assembly macro logic.
 *
 * ev: Event flag (0 for use T0/calc T1, 1 for use T1/calc T0)
 * rc: Round Constant vector (v<rc_reg>.4s)
 * s0: Message word vector (v<s0_reg>.4s) - Can be empty for the last round.
 */
#define ADD_ONLY_CE(ev, rc, s0) \
    "mov        v26.16b, v24.16b\n\t" \
    ".ifne " #ev " - 1\n\t" /* Branch 1: ev == 0 (Use T0, calculate T1) */ \
    /* Calculate T1: t1 = v<s0> + v<rc> */ \
    ADD_IF_NOT_EMPTY(23, s0, rc) \
    "sha256h    q24, q25, v22.4s\n\t" \
    "sha256h2   q25, q26, v22.4s\n\t" \
    ".else\n\t" /* Branch 2: ev == 1 (Use T1, calculate T0) */ \
    /* Calculate T0: t0 = v<s0> + v<rc>. Omit if s0 is empty. */ \
    ".ifnb " #s0 "\n\t" \
    ADD_IF_NOT_EMPTY(22, s0, rc) \
    ".endif\n\t" \
    "sha256h    q24, q25, v23.4s\n\t" \
    "sha256h2   q25, q26, v23.4s\n\t" \
    ".endif\n\t"

/*
 * Macro replicating the 'add_update' assembly macro logic.
 */
#define ADD_UPDATE_CE(ev, rc, s0, s1, s2, s3) \
    "sha256su0  v" #s0 ".4s, v" #s1 ".4s\n\t" \
    ADD_ONLY_CE(ev, rc, s1) \
    "sha256su1  v" #s0 ".4s, v" #s2 ".4s, v" #s3 ".4s\n\t"

/*
 * Performs the core SHA-256 transform on one or more blocks using
 * ARM Crypto Extensions.
 */
static void SHA256_ce_transform(uint32_t *state, const unsigned char *buf, int blocks)
{
  /* The core logic relies on ARMv8-a+crypto features. */
  __asm__ __volatile__(
    ".arch        armv8-a+crypto\n\t"

    /* load round constants */
    "mov        x8, %3\n\t"
    "ld1        { v0.4s- v3.4s}, [x8], #64\n\t"
    "ld1        { v4.4s- v7.4s}, [x8], #64\n\t"
    "ld1        { v8.4s-v11.4s}, [x8], #64\n\t"
    "ld1        {v12.4s-v15.4s}, [x8]\n\t"

    /* load state */
    "mov        x9, %0\n\t"
    "ld1        {v20.4s}, [x9], #16\n\t"
    "ld1        {v21.4s}, [x9]\n\t"

    /* Loop start */
    "0:\n\t"
    /* load input */
    "ld1        {v16.16b-v19.16b}, [%1], #64\n\t"
    "sub        %w2, %w2, #1\n\t"

    /* Byte-swap the input words (Big-endian conversion) */
    "rev32      v16.16b, v16.16b\n\t"
    "rev32      v17.16b, v17.16b\n\t"
    "rev32      v18.16b, v18.16b\n\t"
    "rev32      v19.16b, v19.16b\n\t"

    /* Core Transform Rounds */
    "1:\n\t"
    /* t=0..3: Initialize T0 and copy state */
    "add        v22.4s, v16.4s, v0.4s\n\t" /* T0 = W[0..3] + K[0..3] */
    "mov        v24.16b, v20.16b\n\t"      /* DG0 = DGA copy */
    "mov        v25.16b, v21.16b\n\t"      /* DG1 = DGB copy */

    /* Step 1: Rounds 4-7 */
    ADD_UPDATE_CE(0, 1, 16, 17, 18, 19)
    /* Step 2: Rounds 8-11 */
    ADD_UPDATE_CE(1, 2, 17, 18, 19, 16)
    /* Step 3: Rounds 12-15 */
    ADD_UPDATE_CE(0, 3, 18, 19, 16, 17)
    /* Step 4: Rounds 16-19 */
    ADD_UPDATE_CE(1, 4, 19, 16, 17, 18)
    /* Step 5: Rounds 20-23 */
    ADD_UPDATE_CE(0, 5, 16, 17, 18, 19)
    /* Step 6: Rounds 24-27 */
    ADD_UPDATE_CE(1, 6, 17, 18, 19, 16)
    /* Step 7: Rounds 28-31 */
    ADD_UPDATE_CE(0, 7, 18, 19, 16, 17)
    /* Step 8: Rounds 32-35 */
    ADD_UPDATE_CE(1, 8, 19, 16, 17, 18)
    /* Step 9: Rounds 36-39 */
    ADD_UPDATE_CE(0, 9, 16, 17, 18, 19)
    /* Step 10: Rounds 40-43 */
    ADD_UPDATE_CE(1, 10, 17, 18, 19, 16)
    /* Step 11: Rounds 44-47 */
    ADD_UPDATE_CE(0, 11, 18, 19, 16, 17)
    /* Step 12: Rounds 48-51 */
    ADD_UPDATE_CE(1, 12, 19, 16, 17, 18)

    /* Step 13: Rounds 52-55 */
    ADD_ONLY_CE(0, 13, 17)
    /* Step 14: Rounds 56-59 */
    ADD_ONLY_CE(1, 14, 18)
    /* Step 15: Rounds 60-63 */
    ADD_ONLY_CE(0, 15, 19)
    /* Step 16: Final round (s0 is empty, only uses T1) */
    ADD_ONLY_CE(1, , )

    /* update state */
    "add        v20.4s, v20.4s, v24.4s\n\t"
    "add        v21.4s, v21.4s, v25.4s\n\t"

    /* handled all input blocks? */
    "cbnz       %w2, 0b\n\t"

    /* store new state */
    "3:\n\t"
    "mov        x9, %0\n\t"
    "st1        {v20.16b}, [x9], #16\n\t"
    "st1        {v21.16b}, [x9]\n\t"

    : "+r" (state),
      "+r" (buf),
      "+r" (blocks)
     : "r" (&sha256_k)
     : "x8", "x9", "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7",
     "v8", "v9", "v10", "v11", "v12", "v13", "v14", "v15",
     "v16", "v17", "v18", "v19", "v20", "v21", "v22", "v23",
     "v24", "v25", "v26", "cc", "memory"
    );
}

void SHA256_transform(AvbSHA256ImplCtx* ctx, const uint8_t* message, size_t block_nb)
{
  if (block_nb)
    SHA256_ce_transform(ctx->h, message, block_nb);
}
