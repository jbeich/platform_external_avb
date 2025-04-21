/*
 * Copyright (C) 2016 The Android Open Source Project
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

#include "avb_crypto.h"
#include "avb_rsa.h"
#include "avb_sha.h"
#include "avb_util.h"

size_t avb_get_algorithm_hash_size(AvbAlgorithmType algorithm) {
  switch (algorithm) {
    case AVB_ALGORITHM_TYPE_NONE:
      return 0;
    case AVB_ALGORITHM_TYPE_SHA256_RSA2048:
    case AVB_ALGORITHM_TYPE_SHA256_RSA4096:
    case AVB_ALGORITHM_TYPE_SHA256_RSA8192:
      return AVB_SHA256_DIGEST_SIZE;
    case AVB_ALGORITHM_TYPE_SHA512_RSA2048:
    case AVB_ALGORITHM_TYPE_SHA512_RSA4096:
    case AVB_ALGORITHM_TYPE_SHA512_RSA8192:
      return AVB_SHA512_DIGEST_SIZE;
    default:
      return SIZE_MAX;
  }
}

bool avb_rsa_public_key_header_validate_and_byteswap(
    const AvbRSAPublicKeyHeader* src, AvbRSAPublicKeyHeader* dest) {
  avb_memcpy(dest, src, sizeof(AvbRSAPublicKeyHeader));

  dest->key_num_bits = avb_be32toh(dest->key_num_bits);
  dest->n0inv = avb_be32toh(dest->n0inv);

  return true;
}
