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

#ifndef AVB_FORCE_HASH_OPS
// hash_ops may be not provided at run-time. Provide default implementation.

#include "avb_util.h"

/* Hash init using compile-time provided implementation */
static void default_init(AvbHashOps* ops, AvbDigestType type) {
  AvbCompileTimeHashOps* hash_ops = (AvbCompileTimeHashOps*)ops;
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
  AvbCompileTimeHashOps* hash_ops = (AvbCompileTimeHashOps*)ops;
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
  AvbCompileTimeHashOps* hash_ops = (AvbCompileTimeHashOps*)ops;
  switch (hash_ops->type) {
    case AVB_DIGEST_TYPE_SHA256:
      return avb_sha256_final(&hash_ops->sha256_context);
    case AVB_DIGEST_TYPE_SHA512:
      return avb_sha512_final(&hash_ops->sha512_context);
    default:
      avb_fatal("Invalid hash_ops type");
  }
}

/* Check run-time provided hash ops and fall-back to compile-time provided in
 * case it's not presented */
AvbHashOps* or_default_hash_ops(AvbHashOps* hash_ops,
                                AvbCompileTimeHashOps* default_ops) {
  if (hash_ops) return hash_ops;

  avb_assert(default_ops != NULL);
  default_ops->ops.init = default_init;
  default_ops->ops.update = default_update;
  default_ops->ops.finalize = default_finalize;

  return (AvbHashOps*)default_ops;
}

#endif  // AVB_FORCE_HASH_OPS
