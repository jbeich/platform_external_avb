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

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#define UNPACK32(x, str)                 \
  {                                      \
    *((str) + 3) = (uint8_t)((x));       \
    *((str) + 2) = (uint8_t)((x) >> 8);  \
    *((str) + 1) = (uint8_t)((x) >> 16); \
    *((str) + 0) = (uint8_t)((x) >> 24); \
  }

#define PACK32(str, x)                                                    \
  {                                                                       \
    *(x) = ((uint32_t) * ((str) + 3)) | ((uint32_t) * ((str) + 2) << 8) | \
           ((uint32_t) * ((str) + 1) << 16) |                             \
           ((uint32_t) * ((str) + 0) << 24);                              \
  }

static const uint32_t sha256_h0[8] = {0x6a09e667,
                                      0xbb67ae85,
                                      0x3c6ef372,
                                      0xa54ff53a,
                                      0x510e527f,
                                      0x9b05688c,
                                      0x1f83d9ab,
                                      0x5be0cd19};

const uint32_t sha256_k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

/* SHA-256 implementation */
void avb_sha256_init(AvbSHA256Ctx* avb_ctx)
{
    AvbSHA256ImplCtx* ctx = (AvbSHA256ImplCtx*)avb_ctx->reserved;

    for (int i = 0; i < ARRAY_SIZE(sha256_seq); i++) {
        ctx->h[sha256_seq[i]] = sha256_h0[i];
    }

    ctx->len = 0;
    ctx->tot_len = 0;
    avb_memset(ctx->block, 0, sizeof(ctx->block));
}

void avb_sha256_update(AvbSHA256Ctx* avb_ctx, const uint8_t* data, size_t len) {
  AvbSHA256ImplCtx* ctx = (AvbSHA256ImplCtx*)avb_ctx->reserved;
  size_t block_nb;
  size_t new_len, rem_len, tmp_len;
  const uint8_t* shifted_data;

  tmp_len = AVB_SHA256_BLOCK_SIZE - ctx->len;
  rem_len = len < tmp_len ? len : tmp_len;

  avb_memcpy(&ctx->block[ctx->len], data, rem_len);

  if (ctx->len + len < AVB_SHA256_BLOCK_SIZE) {
    ctx->len += len;
    return;
  }

  new_len = len - rem_len;
  block_nb = new_len / AVB_SHA256_BLOCK_SIZE;

  shifted_data = data + rem_len;

  SHA256_transform(ctx, ctx->block, 1);
  if (block_nb)
	  SHA256_transform(ctx, shifted_data, block_nb);

  rem_len = new_len % AVB_SHA256_BLOCK_SIZE;

  avb_memcpy(ctx->block, &shifted_data[block_nb << 6], rem_len);

  ctx->len = rem_len;
  ctx->tot_len += (block_nb + 1) << 6;
}

uint8_t* avb_sha256_final(AvbSHA256Ctx* avb_ctx) {
  AvbSHA256ImplCtx* ctx = (AvbSHA256ImplCtx*)avb_ctx->reserved;
  size_t block_nb;
  size_t pm_len;
  uint64_t len_b;

  block_nb =
      (1 + ((AVB_SHA256_BLOCK_SIZE - 9) < (ctx->len % AVB_SHA256_BLOCK_SIZE)));

  len_b = (ctx->tot_len + ctx->len) << 3;
  pm_len = block_nb << 6;

  avb_memset(ctx->block + ctx->len, 0, pm_len - ctx->len);
  ctx->block[ctx->len] = 0x80;
  UNPACK32(len_b, ctx->block + pm_len - 4);

  SHA256_transform(ctx, ctx->block, block_nb);

  for (int i = 0; i < ARRAY_SIZE(sha256_seq); i++) {
    UNPACK32(ctx->h[sha256_seq[i]], &avb_ctx->buf[i * 4]);
  }

  return avb_ctx->buf;
}
