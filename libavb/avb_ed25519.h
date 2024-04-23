#ifndef AVB_ED25519_H
#define AVB_ED25519_H
#include "avb_sysdeps.h"

// ED25519_sign sets |out_sig| to be a signature of |message_len| bytes from
// |message| using |private_key|. It returns one on success or zero on
// allocation failure.
int avb_ED25519_sign(uint8_t out_sig[64],
                     const uint8_t* message,
                     size_t message_len,
                     const uint8_t private_key[64]);

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
                                   const uint8_t seed[32]);

#endif  // AVB_ED25519_H
