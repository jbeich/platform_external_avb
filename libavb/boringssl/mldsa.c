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

#include <openssl/bytestring.h>
#include <openssl/mldsa.h>

#include "../avb_mldsa.h"
#include "../avb_sysdeps.h"
#include "../avb_util.h"

bool avb_mldsa_prehash_init_impl(AvbMLDSAPrehashCtx* ctx,
                                 AvbAlgorithmType algorithm,
                                 const uint8_t* key,
                                 size_t key_num_bytes,
                                 const uint8_t* context,
                                 size_t context_len) {
  if (ctx == NULL) {
    return false;
  }
  avb_memset(ctx, 0, sizeof(AvbMLDSAPrehashCtx));
  ctx->algorithm = algorithm;
  CBS cbs;
  CBS_init(&cbs, key, key_num_bytes);

  switch (algorithm) {
    case AVB_ALGORITHM_TYPE_MLDSA65: {
      struct MLDSA65_public_key mldsa65_key;
      if (1 != MLDSA65_parse_public_key(&mldsa65_key, &cbs)) {
        avb_error("Failed to parse ML-DSA-65 public key.\n");
        return false;
      }
      MLDSA65_prehash_init(
          &ctx->ctx.mldsa65, &mldsa65_key, context, context_len);
      break;
    }
    case AVB_ALGORITHM_TYPE_MLDSA87: {
      struct MLDSA87_public_key mldsa87_key;
      if (1 != MLDSA87_parse_public_key(&mldsa87_key, &cbs)) {
        avb_error("Failed to parse ML-DSA-87 public key.\n");
        return false;
      }
      MLDSA87_prehash_init(
          &ctx->ctx.mldsa87, &mldsa87_key, context, context_len);
      break;
    }
    default:
      avb_error("Unsupported ML-DSA algorithm type.\n");
      return false;
  }
  return true;
}

void avb_mldsa_prehash_update(AvbMLDSAPrehashCtx* ctx,
                              const uint8_t* data,
                              size_t data_len) {
  if (ctx == NULL || data == NULL || data_len == 0) {
    return;
  }
  switch (ctx->algorithm) {
    case AVB_ALGORITHM_TYPE_MLDSA65:
      MLDSA65_prehash_update(&ctx->ctx.mldsa65, data, data_len);
      break;
    case AVB_ALGORITHM_TYPE_MLDSA87:
      MLDSA87_prehash_update(&ctx->ctx.mldsa87, data, data_len);
      break;
    default:
      break;
  }
}

bool avb_mldsa_prehash_finalize(AvbMLDSAPrehashCtx* ctx,
                                uint8_t out_msg_rep[AVB_MLDSA_MU_BYTES]) {
  if (ctx == NULL || out_msg_rep == NULL) {
    return false;
  }
  switch (ctx->algorithm) {
    case AVB_ALGORITHM_TYPE_MLDSA65:
      MLDSA65_prehash_finalize(out_msg_rep, &ctx->ctx.mldsa65);
      break;
    case AVB_ALGORITHM_TYPE_MLDSA87:
      MLDSA87_prehash_finalize(out_msg_rep, &ctx->ctx.mldsa87);
      break;
    default:
      return false;
  }
  return true;
}

bool avb_mldsa_verify_message_representative_impl(
    AvbAlgorithmType algorithm,
    const uint8_t* key,
    size_t key_num_bytes,
    const uint8_t* sig,
    size_t sig_num_bytes,
    const uint8_t msg_rep[AVB_MLDSA_MU_BYTES]) {
  CBS cbs;
  CBS_init(&cbs, key, key_num_bytes);

  switch (algorithm) {
    case AVB_ALGORITHM_TYPE_MLDSA65: {
      struct MLDSA65_public_key mldsa65_key;
      if (1 != MLDSA65_parse_public_key(&mldsa65_key, &cbs)) {
        avb_error("Failed to parse ML-DSA-65 public key.\n");
        return false;
      }
      return 1 == MLDSA65_verify_message_representative(
                      &mldsa65_key, sig, sig_num_bytes, msg_rep);
    }
    case AVB_ALGORITHM_TYPE_MLDSA87: {
      struct MLDSA87_public_key mldsa87_key;
      if (1 != MLDSA87_parse_public_key(&mldsa87_key, &cbs)) {
        avb_error("Failed to parse ML-DSA-87 public key.\n");
        return false;
      }
      return 1 == MLDSA87_verify_message_representative(
                      &mldsa87_key, sig, sig_num_bytes, msg_rep);
    }
    default:
      avb_error("Unsupported ML-DSA algorithm type.\n");
      return false;
  }
}
