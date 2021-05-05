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

#include <libavb/avb_ed25519.h>
#include <openssl/curve25519.h>
#include <openssl/is_boringssl.h>

void avb_ed25519_keypair_from_seed(uint8_t out_public_key[32],
                                   uint8_t out_private_key[64],
                                   const uint8_t seed[32]) {
  ED25519_keypair_from_seed(out_public_key, out_private_key, seed);
}

bool avb_ed25519_sign(uint8_t out_signature[64],
                      const uint8_t* message,
                      size_t message_len,
                      const uint8_t private_key[64]) {
  return 1 == ED25519_sign(out_signature, message, message_len, private_key);
}

/* Verifies that the signature is valid for the message with the public key. */
bool avb_ed25519_verify(const uint8_t* message,
                        size_t message_len,
                        const uint8_t signature[64],
                        const uint8_t public_key[32]) {
  return 1 == ED25519_verify(message, message_len, signature, public_key);
}
