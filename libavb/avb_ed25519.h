/*
 * Copyright (C) 2021 The Android Open Source Project
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
#error "You can't include avb_ed25519.h in the public header libavb.h."
#endif

#ifndef AVB_COMPILATION
#error "Never include this file, it may only be used from internal avb code."
#endif

#ifndef AVB_ED25519_H_
#define AVB_ED25519_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "avb_sysdeps.h"

/* Calculates a public and private key from an Ed25519 seed. */
void avb_ed25519_keypair_from_seed(uint8_t out_public_key[32],
                                   uint8_t out_private_key[64],
                                   const uint8_t seed[32]);

/* Calculates the signature of the message using the private key. */
bool avb_ed25519_sign(uint8_t out_signature[64],
                      const uint8_t* message,
                      size_t message_len,
                      const uint8_t private_key[64])
    AVB_ATTR_WARN_UNUSED_RESULT;

/* Verifies that the signature is valid for the message with the public key. */
bool avb_ed25519_verify(const uint8_t* message,
                        size_t message_len,
                        const uint8_t signature[64],
                        const uint8_t public_key[32])
    AVB_ATTR_WARN_UNUSED_RESULT;

#ifdef __cplusplus
}
#endif

#endif /* AVB_ED25519_H_ */
