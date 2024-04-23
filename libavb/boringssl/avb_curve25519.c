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

#include "../avb_ed25519.h"
#include "avb_crypto_ops_impl.h"

// ED25519_sign sets |out_sig| to be a signature of |message_len| bytes from
// |message| using |private_key|. It returns one on success or zero on
// allocation failure.
int avb_ED25519_sign(uint8_t out_sig[64],
                     const uint8_t* message,
                     size_t message_len,
                     const uint8_t private_key[64]) {
  return ED25519_sign(out_sig, message, message_len, private_key);
}

// ED25519_verify returns one iff |signature| is a valid signature, by
// |public_key| of |message_len| bytes from |message|. It returns zero
// otherwise.
// int ED25519_verify(const uint8_t *message, size_t message_len,
//                                  const uint8_t signature[64],
//                                  const uint8_t public_key[32]);

// ED25519_keypair_from_seed calculates a public and private key from an
// Ed25519 “seed”. Seed values are not exposed by this API (although they
// happen to be the first 32 bytes of a private key) so this function is for
// interoperating with systems that may store just a seed instead of a full
// private key.
void avb_ED25519_keypair_from_seed(uint8_t out_public_key[32],
                                   uint8_t out_private_key[64],
                                   const uint8_t seed[32]) {
  ED25519_keypair_from_seed(out_public_key, out_private_key, seed);
}
