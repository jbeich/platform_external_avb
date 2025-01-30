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

#ifdef AVB_INSIDE_LIBAVB_H
#error "You can't include avb_sha.h in the public header libavb.h."
#endif

#ifndef AVB_COMPILATION
#error "Never include this file, it may only be used from internal avb code."
#endif

#ifndef AVB_SHA_H_
#define AVB_SHA_H_

#ifdef __cplusplus
extern "C" {
#endif

/* AVB_FORCE_HASH_OPS is a compiler flag that forces libavb to rely entirely on
 * the HashOps interface specified by `AvbOps.hash_ops`. This eliminates the
 * need for compile-time hash implementations (e.g., AVB_SHA256_CONTEXT_SIZE,
 * avb_sha256_init, etc.), but requires a valid HashOps back-end. See avb_ops.h
 * for details.
 *
 * If AVB_FORCE_HASH_OPS is not defined, libavb will still prefer
 * `AvbOps.hash_ops` but will fall back to the compile-time hash
 * implementations, which must then be provided.
 */
#ifdef AVB_FORCE_HASH_OPS

/* HashOps are requred to be provided at run-time. Ensure it before use. */
#define AVB_PREPARE_HASH_OPS(var_name, hash_ops) \
  avb_assert(hash_ops != NULL);                  \
  AvbHashOps* var_name = hash_ops;

#else

#include "avb_crypto.h"
#include "avb_ops.h"
#include "avb_sysdeps.h"

/* The following defines must be set to something appropriate
 *
 *   AVB_SHA256_CONTEXT_SIZE - the size of AvbSHA256Ctx, excluding the buffer
 *   AVB_SHA512_CONTEXT_SIZE - the size of AvbSHA512Ctx, exclusing the buffer
 *
 * For example, if AvbSHA512Ctx is implemented using BoringSSL this would be
 * defined as sizeof(SHA256_CTX).
 *
 * We expect the implementation to provide a header file with the name
 * avb_crypto_ops_impl.h to do all this.
 */
#include "avb_crypto_ops_impl.h"

/* Data structure used for SHA-256. */
typedef struct {
  uint8_t reserved[AVB_SHA256_CONTEXT_SIZE];
  uint8_t buf[AVB_SHA256_DIGEST_SIZE]; /* Used for storing the final digest. */
} AvbSHA256Ctx;

/* Data structure used for SHA-512. */
typedef struct {
  uint8_t reserved[AVB_SHA512_CONTEXT_SIZE];
  uint8_t buf[AVB_SHA512_DIGEST_SIZE]; /* Used for storing the final digest. */
} AvbSHA512Ctx;

/* AvbHashOps using compile-time provided implementation.
 * AvbCompileTimeHashOps.ops must be initialized by `or_default_hash_ops` before
 * use. Pointer to AvbCompileTimeHashOps is binary compatible with AvbHashOps
 * from avb_ops.h.
 */
typedef struct {
  AvbHashOps ops;
  AvbDigestType type;
  union {
    AvbSHA256Ctx sha256_context;
    AvbSHA512Ctx sha512_context;
  };
} AvbCompileTimeHashOps;

/* Check run-time provided hash ops and fall-back to compile-time provided in
 * case it's not */
AvbHashOps* or_default_hash_ops(AvbHashOps* ops,
                                AvbCompileTimeHashOps* default_ops);

/* HashOps may not be available, check this and use compile-time provided hash
 * implementation. */
#define AVB_PREPARE_HASH_OPS(var_name, hash_ops) \
  AvbCompileTimeHashOps default_ops;             \
  AvbHashOps* var_name = or_default_hash_ops(hash_ops, &default_ops);

/* Initializes the SHA-256 context. */
void avb_sha256_init(AvbSHA256Ctx* ctx);

/* Updates the SHA-256 context with |len| bytes from |data|. */
void avb_sha256_update(AvbSHA256Ctx* ctx, const uint8_t* data, size_t len);

/* Returns the SHA-256 digest. */
uint8_t* avb_sha256_final(AvbSHA256Ctx* ctx) AVB_ATTR_WARN_UNUSED_RESULT;

/* Initializes the SHA-512 context. */
void avb_sha512_init(AvbSHA512Ctx* ctx);

/* Updates the SHA-512 context with |len| bytes from |data|. */
void avb_sha512_update(AvbSHA512Ctx* ctx, const uint8_t* data, size_t len);

/* Returns the SHA-512 digest. */
uint8_t* avb_sha512_final(AvbSHA512Ctx* ctx) AVB_ATTR_WARN_UNUSED_RESULT;

#endif /* AVB_FORCE_HASH_OPS */

#ifdef __cplusplus
}
#endif

#endif /* AVB_SHA_H_ */
