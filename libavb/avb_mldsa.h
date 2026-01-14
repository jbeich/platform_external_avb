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

#ifdef AVB_INSIDE_LIBAVB_H
#error "You can't include avb_mldsa.h in the public header libavb.h."
#endif

#ifndef AVB_COMPILATION
#error "Never include this file, it may only be used from internal avb code."
#endif

#ifndef AVB_MLDSA_H_
#define AVB_MLDSA_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "avb_crypto.h"
#include "avb_crypto_ops_impl.h"
#include "avb_sysdeps.h"

/* The header for a serialized ML-DSA public key.
 *
 * Following this header is |key_num_bytes| bytes of the public key, serialized
 * according to FIPS 204, Algorithm 22 (`pkEncode`).
 *
 * All fields in this struct are stored in network byte order when
 * serialized.  To generate a copy with fields swapped to native byte
 * order, use the function avb_mldsa_public_key_header_validate_and_byteswap().
 *
 * The `avb_mldsa_prehash_init()` and
 * `avb_mldsa_verify_message_representative()` functions expect a key in this
 * serialized format.
 *
 * The 'avbtool extract_public_key' command can be used to generate a
 * serialized ML-DSA public key.
 */
typedef struct AvbMLDSAPublicKeyHeader {
  uint32_t key_num_bytes;
} AVB_ATTR_PACKED AvbMLDSAPublicKeyHeader;

/* Copies |src| to |dest| and validates, byte-swapping fields in the
 * process if needed. Returns true if valid, false if invalid.
 */
bool avb_mldsa_public_key_header_validate_and_byteswap(
    const AvbMLDSAPublicKeyHeader* src,
    AvbMLDSAPublicKeyHeader* dest) AVB_ATTR_WARN_UNUSED_RESULT;

#define AVB_MLDSA_MU_BYTES 64

struct AvbMLDSAPrehashCtx {
  AvbAlgorithmType algorithm;
  union {
    AvbMLDSA65PrehashImplCtx mldsa65;
    AvbMLDSA87PrehashImplCtx mldsa87;
  } ctx;
};
typedef struct AvbMLDSAPrehashCtx AvbMLDSAPrehashCtx;

/* Initializes the prehashing context with the given algorithm and key.
 * The key is expected to be in the format described in
 * `AvbMLDSAPublicKeyHeader`.
 *
 * @ctx: The context to initialize.
 * @algorithm: The ML-DSA algorithm type.
 * @key: Pointer to the serialized public key.
 * @key_num_bytes: The size of the serialized public key.
 * @context: Optional context string for domain separation.
 * @context_len: The length of the context string.
 *
 * Returns true on success, false on failure.
 */
bool avb_mldsa_prehash_init(AvbMLDSAPrehashCtx* ctx,
                            AvbAlgorithmType algorithm,
                            const uint8_t* key,
                            size_t key_num_bytes,
                            const uint8_t* context,
                            size_t context_len);

/* Updates the prehashing operation with a chunk of data.
 *
 * @ctx: The prehashing context.
 * @data: Pointer to the data chunk.
 * @data_len: The length of the data chunk.
 */
void avb_mldsa_prehash_update(AvbMLDSAPrehashCtx* ctx,
                              const uint8_t* data,
                              size_t data_len);

/* Finalizes the prehashing and outputs the message representative (mu).
 *
 * @ctx: The prehashing context.
 * @out_msg_rep: Output buffer for the message representative (must be
 * AVB_MLDSA_MU_BYTES).
 *
 * Returns true on success, false on failure.
 */
bool avb_mldsa_prehash_finalize(AvbMLDSAPrehashCtx* ctx,
                                uint8_t out_msg_rep[AVB_MLDSA_MU_BYTES]);

/* Verifies the ML-DSA signature against the precomputed message representative.
 * The key is expected to be in the format described in
 * `AvbMLDSAPublicKeyHeader`.
 *
 * @algorithm: The ML-DSA algorithm type.
 * @key: Pointer to the serialized public key.
 * @key_num_bytes: The size of the serialized public key.
 * @sig: Pointer to the signature.
 * @sig_num_bytes: The size of the signature.
 * @msg_rep: The precomputed message representative (AVB_MLDSA_MU_BYTES).
 *
 * Returns true if the signature is valid, false otherwise.
 */
bool avb_mldsa_verify_message_representative(
    AvbAlgorithmType algorithm,
    const uint8_t* key,
    size_t key_num_bytes,
    const uint8_t* sig,
    size_t sig_num_bytes,
    const uint8_t msg_rep[AVB_MLDSA_MU_BYTES]);

bool avb_mldsa_verify_message_representative_impl(
    AvbAlgorithmType algorithm,
    const uint8_t* key,
    size_t key_num_bytes,
    const uint8_t* sig,
    size_t sig_num_bytes,
    const uint8_t msg_rep[AVB_MLDSA_MU_BYTES]);

bool avb_mldsa_prehash_init_impl(AvbMLDSAPrehashCtx* ctx,
                                 AvbAlgorithmType algorithm,
                                 const uint8_t* key,
                                 size_t key_num_bytes,
                                 const uint8_t* context,
                                 size_t context_len);

#ifdef __cplusplus
}
#endif

#endif /* AVB_MLDSA_H_ */
