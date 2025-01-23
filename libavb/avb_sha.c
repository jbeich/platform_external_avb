/*
 * Copyright (C) 2024 The Android Open Source Project
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

#include "avb_sha.h"

#include "avb_util.h"

#ifdef AVB_FORCE_HASH_OPS
// hash_ops must be provided at run-time.

AvbHashOps* or_default_hash_ops(AvbHashOps* hash_ops) {
  if (hash_ops == NULL) {
    avb_fatal("Hash ops must be probided at run-time.\n");
  }
  return hash_ops;
}

#else
// hash_ops may be not provided at run-time. Provide default implementation.

/* AvbHashOps using compile-time provided implementation.
 * Pointer to DefaultAvbHashOps is binary compatible with AvbHashOps from
 * avb_ops.h.
 */
typedef struct {
  AvbHashOps ops;
  AvbDigestType type;
  AvbSHA256Ctx sha256_context;
  AvbSHA512Ctx sha512_context;
} DefaultAvbHashOps;

/* Hash init using compile-time provided implementation */
static void default_init(AvbHashOps* ops, AvbDigestType type) {
  DefaultAvbHashOps* hash_ops = (DefaultAvbHashOps*)ops;
  hash_ops->type = type;
  switch (hash_ops->type) {
    case AVB_DIGEST_TYPE_SHA256:
      avb_sha256_init(&hash_ops->sha256_context);
      break;
    case AVB_DIGEST_TYPE_SHA512:
      avb_sha512_init(&hash_ops->sha512_context);
      break;
    default:
      avb_fatal("Invalid hash_ops type");
  }
}

/* Hash update using compile-time provided implementation */
static void default_update(AvbHashOps* ops, const uint8_t* data, size_t len) {
  DefaultAvbHashOps* hash_ops = (DefaultAvbHashOps*)ops;
  switch (hash_ops->type) {
    case AVB_DIGEST_TYPE_SHA256:
      avb_sha256_update(&hash_ops->sha256_context, data, len);
      break;
    case AVB_DIGEST_TYPE_SHA512:
      avb_sha512_update(&hash_ops->sha512_context, data, len);
      break;
    default:
      avb_fatal("Invalid hash_ops type");
  }
}

/* Hash finalize using compile-time provided implementation */
static const uint8_t* default_finalize(AvbHashOps* ops) {
  DefaultAvbHashOps* hash_ops = (DefaultAvbHashOps*)ops;
  switch (hash_ops->type) {
    case AVB_DIGEST_TYPE_SHA256:
      return avb_sha256_final(&hash_ops->sha256_context);
    case AVB_DIGEST_TYPE_SHA512:
      return avb_sha512_final(&hash_ops->sha512_context);
    default:
      avb_fatal("Invalid hash_ops type");
  }
}

/* Default hash ops instance which uses compile-time provided implementations */
DefaultAvbHashOps kDefaultAvbHashOps = {
    .ops = {.init = default_init,
            .update = default_update,
            .finalize = default_finalize},
};

AvbHashOps* or_default_hash_ops(AvbHashOps* hash_ops) {
  return hash_ops ? hash_ops : (AvbHashOps*)&kDefaultAvbHashOps;
}

#endif  // AVB_FORCE_HASH_OPS
