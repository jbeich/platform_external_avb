/*
 * Copyright 2024 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "avb_rot.h"

#include "avb_cmdline.h"
#include "avb_ed25519.h"
#include "avb_property_descriptor.h"
#include "avb_rot_dice.h"
#include "avb_sha.h"
#include "avb_sysdeps.h"
#include "avb_util.h"

#define MAJOR_TYPE_MASK 0x07
// Mask for additional information in the low-order 5 bits
#define ADDINFO_MASK 0x1F
// Major type 0: an unsigned integer
#define TYPE_UNSIGNED_INTEGER 0x00
// Major type 1: a negative integer
#define TYPE_NEGATIVE_INTEGER 0x01
// Major type 2: a byte string
#define TYPE_BYTE_STRING 0x02
// Major type 3: a text string
#define TYPE_TEXT_STRING 0x03
// Major type 4: an array of data items
#define TYPE_ARRAY 0x04
// Major type 5: a map of pairs of data items
#define TYPE_MAP 0x05
// Major type 6: optional semantic tagging of other major types
#define TYPE_TAG 0x06
// Major type 7: floating-point numbers
#define TYPE_FLOAT 0x07
/**
 * Length information (Integer size, array length, etc.) in low-order 5 bits
 */
// One byte unsigned value (uint8)
#define ENCODED_ONE_BYTE 0x18
// Two byte unsigned value (uint16)
#define ENCODED_TWO_BYTES 0x19
// Four byte unsigned value (uint32)
#define ENCODED_FOUR_BYTES 0x1a
// Eight byte unsigned value (uint64)
#define ENCODED_EIGHT_BYTES 0x1b

/**
 * Values for additional information in major type 7
 */
// CBOR encoded boolean - false
#define ENCODED_FALSE 0xF4
// CBOR encoded boolean - true
#define ENCODED_TRUE 0xF5
// CBOR encoded null
#define ENCODED_NULL 0xF6
// CBOR encoded undefined value
#define ENCODED_UNDEFINED 0xF7

// CBOR encoded break for unlimited arrays/maps.
#define ENCODED_BREAK 0xFF

#define ERR_OOB false
#define ERR_OK true

// Following defines RoT Data element keys
#define ROT_BOOT_NONCE_KEY 1
#define ROT_VBKEY0_KEY 2
#define ROT_BOOT_LOCKED_KEY 3
#define ROT_VBSTATE_KEY 4
#define ROT_VBMETA_DIGEST_KEY 5
#define ROT_OS_VERSION_KEY 6
#define ROT_OS_PATCH_LVL_KEY 7
#define ROT_VENDOR_PATCH_LVL_KEY 8
#define ROT_BOOT_PATCH_LVL_KEY 9

// Used for Hmac implementation for dice kdf
#define O_KEY_PAD 0x5c
#define I_KEY_PAD 0x36
// Used for certificate subject and id
#define DICE_ID_SIZE 20
// COSE Key alg value from Table 2 of RFC9053
#define DICE_COSE_KEY_ALG_VALUE (-8)
// Max size of COSE_Key encoding.
#define DICE_MAX_PUBLIC_KEY_SIZE (ED25519_PUBLIC_KEY_LEN + 32)
// Max size of the COSE_Sign1 protected attributes.
#define DICE_MAX_PROTECTED_ATTRIBUTES_SIZE 16
// Max signature structure size
#define AVB_ROT_DICE_SIG_STRUCT_MAX_SIZE 256
// SHA Block Sizes
#define AVB_ROT_SHA512_BLOCK_SIZE 128
#define AVB_ROT_SHA256_BLOCK_SIZE 64

#define AVB_ROT_ERROR -1

// Used by avb rot cbor error handling
#define avb_rot_cbor_error(expr, lbl) \
  do {                                \
    if (!(expr)) {                    \
      goto lbl;                       \
    }                                 \
  } while (0)

// Used by avb rot cbor functions
typedef struct {
  uint8_t* buf;
  uint16_t cur;
  uint16_t end;
} CborCtx;

// Enumeration of verified boot state
typedef enum { verified, self_signed, unverified, failed } vb_state_t;

// Fixed salt for dice kdf. This is copied from AOSP's open-dice module.
static const uint8_t kDiceIdSalt[] = {
    0xDB, 0xDB, 0xAE, 0xBC, 0x80, 0x20, 0xDA, 0x9F, 0xF0, 0xDD, 0x5A,
    0x24, 0xC8, 0x3A, 0xA5, 0xA5, 0x42, 0x86, 0xDF, 0xC2, 0x63, 0x03,
    0x1E, 0x32, 0x9B, 0x4D, 0xA1, 0x48, 0x43, 0x06, 0x59, 0xFE, 0x62,
    0xCD, 0xB5, 0xB7, 0xE1, 0xE0, 0x0F, 0xC6, 0x80, 0x30, 0x67, 0x11,
    0xEB, 0x44, 0x4A, 0xF7, 0x72, 0x09, 0x35, 0x94, 0x96, 0xFC, 0xFF,
    0x1D, 0xB9, 0x52, 0x0B, 0xA5, 0x1C, 0x7B, 0x29, 0xEA};
static const size_t kDiceIdSaltSize = 64;

// Used for fixed part of Cose Sign1 Sig Structure for dice
static const uint8_t kDiceCoseSigStructPart[] = {
    // Array of 4 elements
    0x84,
    // "Signature1"
    0x6A,
    0x53,
    0x69,
    0x67,
    0x6E,
    0x61,
    0x74,
    0x75,
    0x72,
    0x65,
    0x31,
    // .bstr containing map {1:-8}
    0x43,
    0xA1,
    0x01,
    0x27,
    // .bstr containing empty aad
    0x40,
    // .bstr payload will be added
};

// Used for fixed part of Cose Sign1 Structure for dice and
// signed RoT data
static const uint8_t kCoseSign1StructPart[] = {
    // #6.18
    0xD2,
    0x84,
    // .bstr {1:-8}
    0x43,
    0xA1,
    0x01,
    0x27,
    //{}- map of 0 elems
    0xA0,
    //.bstr payload will be added
    //.bstr signature will be added
};

// Used for fixed part of Cose Sign1 Sig Structure for RoT data
static const uint8_t kRoTCoseSigStructPart[] = {
    // array(4)
    0x84,
    //.text "Signature1"
    0x6A,
    0x53,
    0x69,
    0x67,
    0x6e,
    0x61,
    0x74,
    0x75,
    0x72,
    0x65,
    0x31,
    // .bstr {1:-8}
    0x43,
    0xA1,
    0x01,
    0x27,
    // .bstr "Bootloader-signed KeyMint RoT"
    0x58,
    0x1D,
    0x42,
    0x6f,
    0x6f,
    0x74,
    0x6c,
    0x6f,
    0x61,
    0x64,
    0x65,
    0x72,
    0x2d,
    0x73,
    0x69,
    0x67,
    0x6e,
    0x65,
    0x64,
    0x20,
    0x4b,
    0x65,
    0x79,
    0x4d,
    0x69,
    0x6e,
    0x74,
    0x20,
    0x52,
    0x6f,
    0x54
    //.bstr Rot Data payload will be added
};

// cbor related methods ---- start
// static uint8_t avb_rot_cbor_get_raw_byte(const CborCtx* ctx) {
//  return ctx->buf[ctx->cur];
//}

static void avb_rot_cbor_increase_offset(CborCtx* ctx, uint16_t inc) {
  ctx->cur += inc;
}

static bool avb_rot_cbor_is_out_of_bounds(CborCtx* ctx, uint16_t inc) {
  return (inc + ctx->cur) >= ctx->end;
}

// Android is little endian - so add the number in reverse
static bool avb_rot_cbor_write_uint_as_array(CborCtx* ctx,
                                             uint8_t* value,
                                             size_t size) {
  if (avb_rot_cbor_is_out_of_bounds(ctx, size)) {
    return ERR_OOB;
  }
  for (size_t i = size; i > 0; i--) {
    ctx->buf[ctx->cur] = value[i - 1];
    avb_rot_cbor_increase_offset(ctx, 1);
  }
  return ERR_OK;
}
static bool avb_rot_cbor_write_raw_byte(CborCtx* ctx, uint8_t val) {
  if (avb_rot_cbor_is_out_of_bounds(ctx, 1)) {
    return ERR_OOB;
  }
  ctx->buf[ctx->cur] = val;
  avb_rot_cbor_increase_offset(ctx, 1);
  return ERR_OK;
}
static bool avb_rot_cbor_write_uint8(CborCtx* ctx,
                                     uint8_t type,
                                     uint8_t value) {
  if (avb_rot_cbor_is_out_of_bounds(ctx, 2)) return ERR_OOB;
  avb_rot_cbor_write_raw_byte(ctx, (uint8_t)(type | ENCODED_ONE_BYTE));
  avb_rot_cbor_write_raw_byte(ctx, value);
  return ERR_OK;
}

static bool avb_rot_cbor_write_uint16(CborCtx* ctx,
                                      uint8_t type,
                                      uint16_t value) {
  if (avb_rot_cbor_is_out_of_bounds(ctx, 3)) {
    return ERR_OOB;
  }
  avb_rot_cbor_write_raw_byte(ctx, (uint8_t)(type | ENCODED_TWO_BYTES));
  avb_rot_cbor_write_uint_as_array(ctx, (uint8_t*)&value, 2);
  return ERR_OK;
}

static bool avb_rot_cbor_write_uint32(CborCtx* ctx,
                                      uint8_t type,
                                      uint32_t value) {
  if (avb_rot_cbor_is_out_of_bounds(ctx, 5)) {
    return ERR_OOB;
  }
  avb_rot_cbor_write_raw_byte(ctx, (uint8_t)(type | ENCODED_FOUR_BYTES));
  avb_rot_cbor_write_uint_as_array(ctx, (uint8_t*)&value, 4);
  return ERR_OK;
}

static bool avb_rot_cbor_write_uint64(CborCtx* ctx,
                                      uint8_t type,
                                      uint64_t value) {
  if (avb_rot_cbor_is_out_of_bounds(ctx, 9)) {
    return ERR_OOB;
  }
  avb_rot_cbor_write_raw_byte(ctx, (uint8_t)(type | ENCODED_EIGHT_BYTES));
  avb_rot_cbor_write_uint_as_array(ctx, (uint8_t*)&value, 8);
  return ERR_OK;
}

static bool avb_rot_cbor_write_raw_byte_as_array(CborCtx* ctx,
                                                 const uint8_t* value,
                                                 short offset,
                                                 short length) {
  if (avb_rot_cbor_is_out_of_bounds(ctx, length)) {
    return ERR_OOB;
  }
  value += offset;
  avb_memcpy((ctx->buf + ctx->cur), value, length);
  avb_rot_cbor_increase_offset(ctx, length);
  return ERR_OK;
}

static bool avb_rot_cbor_encode_boolean(CborCtx* ctx, bool value) {
  if (value) {
    return avb_rot_cbor_write_raw_byte(ctx, ENCODED_TRUE);
  } else {
    return avb_rot_cbor_write_raw_byte(ctx, ENCODED_FALSE);
  }
}

// static bool avb_rot_cbor_encode_raw_data(CborCtx* ctx,
//     external/avb/libavb/avb-crypto/curve25519/avb_curve25519.c const uint8_t*
//     value,
//                                          short offset,
//                                          short length) {
//   return avb_rot_cbor_write_raw_byte_as_array(ctx, value, offset, length);
// }

static bool avb_rot_cbor_encode_value(CborCtx* ctx,
                                      uint8_t majorType,
                                      uint64_t value) {
  if (value < ENCODED_ONE_BYTE) {
    return avb_rot_cbor_write_raw_byte(ctx, majorType | value);
  } else if (value < 0x100) {
    return avb_rot_cbor_write_uint8(ctx, majorType, value);
  } else if (value < 0x10000) {
    return avb_rot_cbor_write_uint16(ctx, majorType, value);
  } else if (value < 0x100000000) {
    return avb_rot_cbor_write_uint32(ctx, majorType, value);
  } else {
    return avb_rot_cbor_write_uint64(ctx, majorType, value);
  }
}
static bool avb_rot_cbor_encode_byte_string(CborCtx* ctx,
                                            const uint8_t* byteString,
                                            short offset,
                                            short length) {
  if (!avb_rot_cbor_encode_value(
          ctx, (uint8_t)(TYPE_BYTE_STRING << 5), length)) {
    return ERR_OOB;
  }
  return avb_rot_cbor_write_raw_byte_as_array(ctx, byteString, offset, length);
}

static bool avb_rot_cbor_encode_text_string(CborCtx* ctx,
                                            const uint8_t* textString,
                                            short offset,
                                            short length) {
  if (!avb_rot_cbor_encode_value(
          ctx, (uint8_t)(TYPE_TEXT_STRING << 5), length)) {
    return ERR_OOB;
  }
  return avb_rot_cbor_write_raw_byte_as_array(ctx, textString, offset, length);
}

static bool avb_rot_cbor_encode_uint(CborCtx* ctx, uint64_t val) {
  return avb_rot_cbor_encode_value(
      ctx, (uint8_t)(TYPE_UNSIGNED_INTEGER << 5), val);
}
static bool avb_rot_cbor_encode_neg_int(CborCtx* ctx, int64_t val) {
  return avb_rot_cbor_encode_value(
      ctx, (uint8_t)(TYPE_NEGATIVE_INTEGER << 5), (-1 - val));
}
// static bool avb_rot_cbor_encode_tag(CborCtx* ctx, uint8_t value) {
//   return avb_rot_cbor_encode_value(ctx, (uint8_t)(TYPE_TAG << 5), value);
// }
static bool avb_rot_cbor_start_array(CborCtx* ctx, short arraySize) {
  return avb_rot_cbor_encode_value(ctx, (uint8_t)(TYPE_ARRAY << 5), arraySize);
}

static bool avb_rot_cbor_start_map(CborCtx* ctx, short mapSize) {
  return avb_rot_cbor_encode_value(ctx, (uint8_t)(TYPE_MAP << 5), mapSize);
}

// static bool avb_rot_cbor_start_byte_string(CborCtx* ctx, short length) {
//   return avb_rot_cbor_encode_value(
//       ctx, (uint8_t)(TYPE_BYTE_STRING << 5), length);
// }

// static bool avb_rot_cbor_start_text_string(CborCtx* ctx, short length) {
//   return avb_rot_cbor_encode_value(
//       ctx, (uint8_t)(TYPE_TEXT_STRING << 5), length);
// }
//  Avb RoT Cbor functions ------ end

static int64_t avb_rot_cbor_encode_rot_data(
    int64_t bootNonce,
    uint8_t vbKey0[AVB_SHA256_DIGEST_SIZE],
    bool bootloaderLocked,
    uint8_t state,
    const uint8_t digest[AVB_SHA256_DIGEST_SIZE],
    int64_t osVersion,
    int64_t osPatchLvl,
    int64_t vendorPatchLvl,
    int64_t bootPatchLvl,
    uint8_t rotData[AVB_ROT_MAX_DATA_SIZE]) {
  CborCtx ctx = {.buf = rotData, .cur = 0, .end = AVB_ROT_MAX_DATA_SIZE};
  uint8_t totalElem = 5;
  if (digest == NULL || vbKey0 == NULL || bootNonce < 0) {
    return AVB_ROT_ERROR;
  }
  if (osVersion >= 0) totalElem++;
  if (osPatchLvl >= 0) totalElem++;
  if (vendorPatchLvl >= 0) totalElem++;
  if (bootPatchLvl >= 0) totalElem++;
  avb_rot_cbor_start_map(&ctx, totalElem);
  avb_rot_cbor_error(avb_rot_cbor_encode_uint(&ctx, ROT_BOOT_NONCE_KEY),
                     avb_rot_cbor_encode_rot_data_err);
  avb_rot_cbor_error(avb_rot_cbor_encode_uint(&ctx, (uint64_t)bootNonce),
                     avb_rot_cbor_encode_rot_data_err);
  avb_rot_cbor_error(avb_rot_cbor_encode_uint(&ctx, ROT_VBKEY0_KEY),
                     avb_rot_cbor_encode_rot_data_err);
  avb_rot_cbor_error(
      avb_rot_cbor_encode_byte_string(&ctx, vbKey0, 0, AVB_SHA256_DIGEST_SIZE),
      avb_rot_cbor_encode_rot_data_err);
  avb_rot_cbor_error(avb_rot_cbor_encode_uint(&ctx, ROT_BOOT_LOCKED_KEY),
                     avb_rot_cbor_encode_rot_data_err);
  avb_rot_cbor_error(avb_rot_cbor_encode_boolean(&ctx, bootloaderLocked),
                     avb_rot_cbor_encode_rot_data_err);
  avb_rot_cbor_error(avb_rot_cbor_encode_uint(&ctx, ROT_VBSTATE_KEY),
                     avb_rot_cbor_encode_rot_data_err);
  avb_rot_cbor_error(avb_rot_cbor_encode_uint(&ctx, (uint8_t)state),
                     avb_rot_cbor_encode_rot_data_err);
  avb_rot_cbor_error(avb_rot_cbor_encode_uint(&ctx, ROT_VBMETA_DIGEST_KEY),
                     avb_rot_cbor_encode_rot_data_err);
  avb_rot_cbor_error(
      avb_rot_cbor_encode_byte_string(&ctx, digest, 0, AVB_SHA256_DIGEST_SIZE),
      avb_rot_cbor_encode_rot_data_err);
  avb_rot_cbor_error(avb_rot_cbor_encode_uint(&ctx, ROT_OS_VERSION_KEY),
                     avb_rot_cbor_encode_rot_data_err);
  avb_rot_cbor_error(avb_rot_cbor_encode_uint(&ctx, (uint32_t)osVersion),
                     avb_rot_cbor_encode_rot_data_err);
  avb_rot_cbor_error(avb_rot_cbor_encode_uint(&ctx, ROT_OS_PATCH_LVL_KEY),
                     avb_rot_cbor_encode_rot_data_err);
  avb_rot_cbor_error(avb_rot_cbor_encode_uint(&ctx, (uint32_t)osPatchLvl),
                     avb_rot_cbor_encode_rot_data_err);
  avb_rot_cbor_error(avb_rot_cbor_encode_uint(&ctx, ROT_VENDOR_PATCH_LVL_KEY),
                     avb_rot_cbor_encode_rot_data_err);
  avb_rot_cbor_error(avb_rot_cbor_encode_uint(&ctx, (uint32_t)vendorPatchLvl),
                     avb_rot_cbor_encode_rot_data_err);
  avb_rot_cbor_error(avb_rot_cbor_encode_uint(&ctx, ROT_BOOT_PATCH_LVL_KEY),
                     avb_rot_cbor_encode_rot_data_err);
  avb_rot_cbor_error(avb_rot_cbor_encode_uint(&ctx, (uint32_t)bootPatchLvl),
                     avb_rot_cbor_encode_rot_data_err);
  return ctx.cur;
avb_rot_cbor_encode_rot_data_err:
  return AVB_ROT_ERROR;
}
static int64_t avb_rot_cbor_encode_signing_input(
    uint8_t* rotData,
    uint64_t rotDataLen,
    uint8_t out_signing_input[AVB_ROT_MAX_DATA_SIZE]) {
  // Create the rotSigningDataInput and sign that
  size_t len = sizeof(kRoTCoseSigStructPart);
  avb_memcpy(out_signing_input, kRoTCoseSigStructPart, len);
  // Add payload
  CborCtx ctx = {
      .buf = out_signing_input, .cur = len, .end = AVB_ROT_MAX_DATA_SIZE};
  avb_rot_cbor_error(
      avb_rot_cbor_encode_byte_string(&ctx, rotData, 0, rotDataLen),
      avb_rot_cbor_encode_signing_input_err);
  return ctx.cur;
avb_rot_cbor_encode_signing_input_err:
  return AVB_ROT_ERROR;
}

static int64_t avb_rot_cbor_encode_signed_rot_data(
    uint8_t* rotData,
    uint64_t rotDataLen,
    uint8_t signature[ED25519_SIGNATURE_LEN],
    uint8_t out_signed_data[AVB_ROT_MAX_DATA_SIZE]) {
  uint64_t len = sizeof(kCoseSign1StructPart);
  avb_memcpy(out_signed_data, kCoseSign1StructPart, len);
  // Add payload
  CborCtx ctx = {
      .buf = out_signed_data, .cur = len, .end = AVB_ROT_MAX_DATA_SIZE};
  avb_rot_cbor_error(
      avb_rot_cbor_encode_byte_string(&ctx, rotData, 0, rotDataLen),
      avb_rot_cbor_encode_signed_rot_data_err);
  // Add signature
  avb_rot_cbor_error(avb_rot_cbor_encode_byte_string(
                         &ctx, signature, 0, ED25519_SIGNATURE_LEN),
                     avb_rot_cbor_encode_signed_rot_data_err);
  return ctx.cur;
avb_rot_cbor_encode_signed_rot_data_err:
  return AVB_ROT_ERROR;
}

static void avb_rot_encode_hex(const uint8_t* in,
                               size_t num_bytes,
                               void* out,
                               size_t out_size) {
  const uint8_t kHexMap[16] = "0123456789abcdef";
  size_t in_pos = 0;
  size_t out_pos = 0;
  uint8_t* out_bytes = out;
  for (in_pos = 0; in_pos < num_bytes && out_pos < out_size; ++in_pos) {
    out_bytes[out_pos++] = kHexMap[(in[in_pos] >> 4)];
    if (out_pos < out_size) {
      out_bytes[out_pos++] = kHexMap[in[in_pos] & 0xF];
    }
  }
}

static uint64_t avb_rot_dice_compute_blk_sized_key(
    const uint8_t* key,
    uint64_t keyLen,
    uint64_t macLen,
    uint8_t blkKey[AVB_ROT_SHA512_BLOCK_SIZE]) {
  avb_memset(blkKey, 0, AVB_ROT_SHA512_BLOCK_SIZE);
  uint64_t len = 0;
  if (macLen == AVB_SHA256_DIGEST_SIZE) {
    AvbSHA256Ctx ctx;
    avb_sha256_init(&ctx);
    if (keyLen > AVB_ROT_SHA256_BLOCK_SIZE) {
      avb_sha256_update(&ctx, key, keyLen);
      uint8_t* hash = avb_sha256_final(&ctx);
      avb_memcpy(blkKey, hash, AVB_SHA256_DIGEST_SIZE);
      len = AVB_ROT_SHA256_BLOCK_SIZE;
    } else {
      avb_memcpy(blkKey, key, keyLen);
      len = AVB_ROT_SHA256_BLOCK_SIZE;
    }
  } else {
    AvbSHA512Ctx ctx;
    avb_sha512_init(&ctx);
    if (keyLen > AVB_ROT_SHA512_BLOCK_SIZE) {
      avb_sha512_update(&ctx, key, keyLen);
      uint8_t* hash = avb_sha512_final(&ctx);
      avb_memcpy(blkKey, hash, AVB_SHA512_DIGEST_SIZE);
      len = AVB_ROT_SHA512_BLOCK_SIZE;
    } else {
      avb_memcpy(blkKey, key, keyLen);
      len = AVB_ROT_SHA512_BLOCK_SIZE;
    }
  }
  return len;
}

static void avb_rot_dice_hmac_xor(uint8_t* blkKey,
                                  uint64_t blkKeyLen,
                                  uint8_t padByte) {
  for (uint64_t i = 0; i < blkKeyLen; i++) {
    blkKey[i] = blkKey[i] ^ padByte;
  }
}
static void avb_rot_dice_compute_hmac_hash(const uint8_t* o_pad,
                                           const uint8_t* i_pad,
                                           uint64_t blkKeyLen,
                                           const uint8_t* msg,
                                           uint64_t msgLen,
                                           uint8_t* mac) {
  if (blkKeyLen == AVB_ROT_SHA256_BLOCK_SIZE) {
    AvbSHA256Ctx ctx;
    avb_sha256_init(&ctx);
    avb_sha256_update(&ctx, i_pad, blkKeyLen);
    avb_sha256_update(&ctx, msg, msgLen);
    uint8_t hash[AVB_SHA256_DIGEST_SIZE];
    avb_memcpy(hash, avb_sha256_final(&ctx), AVB_SHA256_DIGEST_SIZE);
    avb_memset(ctx.buf, 0, AVB_SHA256_DIGEST_SIZE);
    avb_memset(ctx.reserved, 0, AVB_SHA256_CONTEXT_SIZE);
    avb_sha256_init(&ctx);
    avb_sha256_update(&ctx, o_pad, blkKeyLen);
    avb_sha256_update(&ctx, hash, AVB_SHA256_DIGEST_SIZE);
    avb_memcpy(mac, avb_sha256_final(&ctx), AVB_SHA256_DIGEST_SIZE);
  } else {
    AvbSHA512Ctx ctx;
    avb_sha512_init(&ctx);
    avb_sha512_update(&ctx, i_pad, blkKeyLen);
    avb_sha512_update(&ctx, msg, msgLen);
    uint8_t hash[AVB_SHA512_DIGEST_SIZE];
    avb_memcpy(hash, avb_sha512_final(&ctx), AVB_SHA512_DIGEST_SIZE);
    avb_memset(ctx.buf, 0, AVB_SHA512_DIGEST_SIZE);
    avb_memset(ctx.reserved, 0, AVB_SHA512_CONTEXT_SIZE);
    avb_sha512_init(&ctx);
    avb_sha512_update(&ctx, o_pad, blkKeyLen);
    avb_sha512_update(&ctx, hash, AVB_SHA512_DIGEST_SIZE);
    avb_memcpy(mac, avb_sha512_final(&ctx), AVB_SHA512_DIGEST_SIZE);
  }
}

/**
 * * Certificatesig_buf = {                  ; sig_buf (RFC8392)
 *     1 : tstr,                       ; Issuer (CDI_ID)
 *     2 : tstr,                       ; |certificate_subject|
 *     -4670552 : bstr                 ; |key_to_sign|
 *     -4670553 : bstr h'0100'         ; key_usage : digitalSignature
 * }
 * This method is copied and modified from open dice implementation
 * from the aosp.
 */
static bool avb_rot_dice_encode_cwt(const char* authority_id_hex,
                                    const char* certificate_subject,
                                    const uint8_t* encoded_public_key,
                                    size_t encoded_public_key_size,
                                    size_t buffer_size,
                                    uint8_t* buffer,
                                    size_t* encoded_size) {
  // Constants per RFC 8392.
  const int64_t ksig_bufIssuerLabel = 1;
  const int64_t ksig_bufSubjectLabel = 2;
  // Constants per the Open Profile for DICE specification.
  const int64_t kSubjectPublicKeyLabel = -4670552;
  const int64_t kKeyUsageLabel = -4670553;
  // Key usage constant per RFC 5280.
  const uint8_t kKeyUsageDigitalSignature = 1;

  // Count the number of entries.
  uint32_t map_pairs = 4;
  // struct CborOut out;
  // CborOutInit(buffer, buffer_size, &out);
  // CborWriteMap(map_pairs, &out);
  CborCtx ctx = {.buf = buffer, .cur = 0, .end = buffer_size};
  avb_rot_cbor_error(avb_rot_cbor_start_map(&ctx, map_pairs),
                     encode_sig_buf_err);
  // Add the issuer.
  // CborWriteInt(ksig_bufIssuerLabel, &out);
  // CborWriteTstr(authority_id_hex, &out);
  avb_rot_cbor_error(avb_rot_cbor_encode_uint(&ctx, ksig_bufIssuerLabel),
                     encode_sig_buf_err);
  avb_rot_cbor_error(
      avb_rot_cbor_encode_text_string(
          &ctx, (uint8_t*)authority_id_hex, 0, avb_strlen(authority_id_hex)),
      encode_sig_buf_err);
  // Add the subject.
  // CborWriteInt(ksig_bufSubjectLabel, &out);
  // CborWriteTstr(subject_id_hex, &out);
  avb_rot_cbor_error(avb_rot_cbor_encode_uint(&ctx, ksig_bufSubjectLabel),
                     encode_sig_buf_err);
  avb_rot_cbor_error(
      avb_rot_cbor_encode_text_string(&ctx,
                                      (uint8_t*)certificate_subject,
                                      0,
                                      avb_strlen(certificate_subject)),
      encode_sig_buf_err);
  // Add the subject public key.
  // CborWriteInt(kSubjectPublicKeyLabel, &out);
  // CborWriteBstr(encoded_public_key_size, encoded_public_key, &out);
  avb_rot_cbor_error(avb_rot_cbor_encode_neg_int(&ctx, kSubjectPublicKeyLabel),
                     encode_sig_buf_err);
  avb_rot_cbor_error(avb_rot_cbor_encode_byte_string(
                         &ctx, encoded_public_key, 0, encoded_public_key_size),
                     encode_sig_buf_err);
  // Add the key usage.
  // CborWriteInt(kKeyUsageLabel, &out);
  // CborWriteBstr(/*data_size=*/1, &key_usage, &out);
  avb_rot_cbor_error(avb_rot_cbor_encode_neg_int(&ctx, kKeyUsageLabel),
                     encode_sig_buf_err);
  avb_rot_cbor_error(
      avb_rot_cbor_encode_byte_string(&ctx, &kKeyUsageDigitalSignature, 0, 1),
      encode_sig_buf_err);
  *encoded_size = ctx.cur;
  return true;
encode_sig_buf_err:
  return false;
}
/**
 * This method is copied and modified from open dice implementation
 * from the aosp.
 */
static bool avb_rot_dice_encode_ed25519_COSE_public_key(
    const uint8_t public_key[ED25519_PUBLIC_KEY_LEN],
    size_t buffer_size,
    uint8_t* buffer,
    size_t* encoded_size) {
  // Constants per RFC 8152.
  const int64_t kCoseKeyKtyLabel = 1;
  const int64_t kCoseKeyAlgLabel = 3;
  const int64_t kCoseKeyOpsLabel = 4;
  const int64_t kCoseOkpCrvLabel = -1;
  const int64_t kCoseOkpXLabel = -2;
  const int64_t kCoseKeyTypeOkp = 1;
  const int64_t kCoseAlgEdDSA = DICE_COSE_KEY_ALG_VALUE;
  const int64_t kCoseKeyOpsVerify = 2;
  const int64_t kCoseCrvEd25519 = 6;

  // CborOutInit(buffer, buffer_size, &out);
  CborCtx ctx = {.buf = buffer, .cur = 0, .end = buffer_size};
  // CborWriteMap(/*num_pairs=*/5, &out);
  avb_rot_cbor_error(avb_rot_cbor_start_map(&ctx, 5),
                     avb_rot_dice_encode_ed25519_COSE_public_key_err);
  // Add the key type.
  // CborWriteInt(kCoseKeyKtyLabel, &out);
  // CborWriteInt(kCoseKeyTypeOkp, &out);
  avb_rot_cbor_error(avb_rot_cbor_encode_uint(&ctx, kCoseKeyKtyLabel),
                     avb_rot_dice_encode_ed25519_COSE_public_key_err);
  avb_rot_cbor_error(avb_rot_cbor_encode_uint(&ctx, kCoseKeyTypeOkp),
                     avb_rot_dice_encode_ed25519_COSE_public_key_err);

  // Add the algorithm.
  // CborWriteInt(kCoseKeyAlgLabel, &out);
  // CborWriteInt(kCoseAlgEdDSA, &out);
  avb_rot_cbor_error(avb_rot_cbor_encode_uint(&ctx, kCoseKeyAlgLabel),
                     avb_rot_dice_encode_ed25519_COSE_public_key_err);
  avb_rot_cbor_error(avb_rot_cbor_encode_neg_int(&ctx, kCoseAlgEdDSA),
                     avb_rot_dice_encode_ed25519_COSE_public_key_err);
  // Add the KeyOps.
  // CborWriteInt(kCoseKeyOpsLabel, &out);
  // CborWriteArray(/*num_elements=*/1, &out);
  // CborWriteInt(kCoseKeyOpsVerify, &out);

  avb_rot_cbor_error(avb_rot_cbor_encode_uint(&ctx, kCoseKeyOpsLabel),
                     avb_rot_dice_encode_ed25519_COSE_public_key_err);
  avb_rot_cbor_error(avb_rot_cbor_start_array(&ctx, 1),
                     avb_rot_dice_encode_ed25519_COSE_public_key_err);
  avb_rot_cbor_error(avb_rot_cbor_encode_uint(&ctx, kCoseKeyOpsVerify),
                     avb_rot_dice_encode_ed25519_COSE_public_key_err);
  // Add the curve.
  // CborWriteInt(kCoseOkpCrvLabel, &out);
  // CborWriteInt(kCoseCrvEd25519, &out);
  avb_rot_cbor_error(avb_rot_cbor_encode_neg_int(&ctx, kCoseOkpCrvLabel),
                     avb_rot_dice_encode_ed25519_COSE_public_key_err);
  avb_rot_cbor_error(avb_rot_cbor_encode_uint(&ctx, kCoseCrvEd25519),
                     avb_rot_dice_encode_ed25519_COSE_public_key_err);
  // Add the public key.
  // CborWriteInt(kCoseOkpXLabel, &out);
  // CborWriteBstr(/*data_size=*/ED25519_PUBLIC_KEY_LEN, public_key, &out);
  avb_rot_cbor_error(avb_rot_cbor_encode_neg_int(&ctx, kCoseOkpXLabel),
                     avb_rot_dice_encode_ed25519_COSE_public_key_err);
  avb_rot_cbor_error(avb_rot_cbor_encode_byte_string(
                         &ctx, public_key, 0, ED25519_PUBLIC_KEY_LEN),
                     avb_rot_dice_encode_ed25519_COSE_public_key_err);
  *encoded_size = ctx.cur;
  return true;
avb_rot_dice_encode_ed25519_COSE_public_key_err:
  return false;
}

static void avb_rot_dice_hmac(const uint8_t* key,
                              uint64_t keyLen,
                              const uint8_t* msg,
                              uint64_t msgLen,
                              uint8_t* mac,
                              uint64_t macLen) {
  uint8_t blkKey[AVB_ROT_SHA512_BLOCK_SIZE];
  uint8_t o_pad[AVB_ROT_SHA512_BLOCK_SIZE];
  uint8_t i_pad[AVB_ROT_SHA512_BLOCK_SIZE];
  // Compute block sized key
  uint64_t blkKeyLen =
      avb_rot_dice_compute_blk_sized_key(key, keyLen, macLen, blkKey);
  // Compute o-pad and i-padED25519_PUBLIC_KEY_L
  avb_memcpy(o_pad, blkKey, blkKeyLen);
  avb_rot_dice_hmac_xor(o_pad, blkKeyLen, O_KEY_PAD);
  avb_memcpy(i_pad, blkKey, blkKeyLen);
  avb_rot_dice_hmac_xor(i_pad, blkKeyLen, I_KEY_PAD);
  // compute hash
  avb_rot_dice_compute_hmac_hash(o_pad, i_pad, blkKeyLen, msg, msgLen, mac);
}

static bool avb_rot_dice_kdf_SHA512(const uint8_t* secret,
                                    uint64_t secretLen,
                                    const uint8_t* salt,
                                    uint64_t salt_len,
                                    const uint8_t* info,
                                    size_t info_len,
                                    uint8_t* output,
                                    uint64_t output_len) {
  if (salt_len <= 0 || output_len <= 0 || secretLen <= 0 || secret == NULL ||
      salt == NULL || output == NULL ||
      output_len > (255 * AVB_SHA512_DIGEST_SIZE)) {
    return false;
  }
  uint8_t prk[AVB_SHA512_DIGEST_SIZE];
  // Extract
  avb_rot_dice_hmac(
      salt, salt_len, secret, secretLen, prk, AVB_SHA512_DIGEST_SIZE);
  // Expand
  uint8_t t[AVB_SHA512_DIGEST_SIZE + info_len + 1];
  avb_memcpy(t, info, info_len);
  uint8_t i = 1;
  t[info_len] = i;
  uint8_t* hash = t;
  uint64_t tLen = info_len + 1;
  ;
  uint64_t offset = 0;

  while (offset < output_len) {
    avb_rot_dice_hmac(
        prk, AVB_SHA512_DIGEST_SIZE, t, tLen, hash, AVB_SHA512_DIGEST_SIZE);
    avb_memcpy(t + AVB_SHA512_DIGEST_SIZE, info, info_len);
    t[AVB_SHA512_DIGEST_SIZE + info_len] = i;
    tLen = AVB_SHA512_DIGEST_SIZE + info_len + 1;
    uint8_t inc = AVB_SHA512_DIGEST_SIZE;
    if (offset + AVB_SHA512_DIGEST_SIZE > output_len) {
      inc = output_len - offset;
    }
    avb_memcpy(output + offset, hash, inc);
    offset += inc;
    i++;
  }
  return true;
}

static bool parse_patchlevel(const char* patchlevel_str, uint32_t* result) {
  bool patchlevel_valid =
      avb_strlen(patchlevel_str) == avb_strlen("YYYY-MM-DD");
  // If the string is the wrong length, `&&` will short-circuit.
  patchlevel_valid = patchlevel_valid && (patchlevel_str[4] == '-');
  patchlevel_valid = patchlevel_valid && (patchlevel_str[7] == '-');
  if (!patchlevel_valid) {
    avb_error("Patchlevel (%s) date format was not YYYY-MM-DD\n",
              patchlevel_str);
    return false;
  }
  char patchlevel_nodashes[sizeof("YYYYMMDD")];
  avb_memcpy(patchlevel_nodashes, patchlevel_str, 4);
  avb_memcpy(&patchlevel_nodashes[4], &patchlevel_str[5], 2);
  avb_memcpy(&patchlevel_nodashes[6], &patchlevel_str[8], 2);
  patchlevel_nodashes[8] = '\0';
  unsigned long result_ul = avb_strtoul(
      patchlevel_nodashes);  // Cover uint32_t / unsigned long mismatch
  if (result_ul == 0) {
    avb_error("Patchlevel (%s) date format was not YYYY-MM-DD\n",
              patchlevel_str);
    return false;
  }
  return true;
}

static bool extract_rot_relevant_data(AvbSlotVerifyData* avb_in,
                                      uint32_t* rot_system_version,
                                      uint32_t* rot_system_patchlevel,
                                      uint32_t* rot_vendor_patchlevel,
                                      uint32_t* rot_boot_patchlevel) {
  static const char system_version_key[] =
      "com.android.build.system.os_version";
  const char* system_version = NULL;

  static const char system_patchlevel_key[] =
      "com.android.build.system.security_patch";
  const char* system_patchlevel = NULL;

  static const char vendor_patchlevel_key[] =
      "com.android.build.vendor.security_patch";
  const char* vendor_patchlevel = NULL;

  static const char boot_patchlevel_key[] =
      "com.android.build.boot.security_patch";
  const char* boot_patchlevel = NULL;

  for (size_t i = 0; i < avb_in->num_vbmeta_images; i++) {
    AvbVBMetaData* p = &avb_in->vbmeta_images[i];
    if (avb_strcmp("vbmeta_system", p->partition_name) == 0) {
      system_version = avb_property_lookup(
          p->vbmeta_data, p->vbmeta_size, system_version_key, 0, NULL);
      system_patchlevel = avb_property_lookup(
          p->vbmeta_data, p->vbmeta_size, system_patchlevel_key, 0, NULL);
    }
    if (avb_strcmp("vbmeta", p->partition_name) == 0) {
      vendor_patchlevel = avb_property_lookup(
          p->vbmeta_data, p->vbmeta_size, vendor_patchlevel_key, 0, NULL);
    }
    if (avb_strcmp("boot", p->partition_name) == 0) {
      boot_patchlevel = avb_property_lookup(
          p->vbmeta_data, p->vbmeta_size, boot_patchlevel_key, 0, NULL);
    }
  }

  if (system_version == NULL) {
    avb_error("AVB was missing %s\n", system_version_key);
    return false;
  }
  unsigned long system_version_ul = avb_strtoul(system_version);
  if (system_version_ul == 0) {
    avb_error("%s had incorrect format, got %s\n",
              system_version_key,
              system_version);
    return false;
  }
  *rot_system_version = system_version_ul;
  if (system_patchlevel == NULL) {
    avb_error("AVB was missing %s\n", system_patchlevel_key);
    return false;
  }
  if (!parse_patchlevel(system_patchlevel, rot_system_patchlevel)) {
    avb_error("%s had incorrect format, got \"%s\"\n",
              system_patchlevel_key,
              system_patchlevel);
    return false;
  }
  if (vendor_patchlevel == NULL) {
    avb_error("AVB was missing %s\n", vendor_patchlevel_key);
    return false;
  }
  if (!parse_patchlevel(vendor_patchlevel, rot_vendor_patchlevel)) {
    avb_error("%s had incorrect format, got \"%s\"\n",
              vendor_patchlevel_key,
              vendor_patchlevel);
    return false;
  }
  if (boot_patchlevel == NULL) {
    avb_error("AVB was missing %s\n", boot_patchlevel_key);
    return false;
  }
  if (!parse_patchlevel(boot_patchlevel, rot_boot_patchlevel)) {
    avb_error("%s had incorrect format, got \"%s\"\n",
              boot_patchlevel_key,
              boot_patchlevel);
    return false;
  }
  return true;
}

bool avb_rot_dice_derive_cert_id(const uint8_t* cdi_public_key,
                                 size_t cdi_public_key_size,
                                 uint8_t* id,
                                 size_t id_size) {
  const uint8_t ID[] = {'I', 'D'};
  bool ret = avb_rot_dice_kdf_SHA512(cdi_public_key,
                                     cdi_public_key_size,
                                     kDiceIdSalt,
                                     kDiceIdSaltSize,
                                     ID,
                                     2,
                                     id,
                                     id_size);

  if (ret) {
    id[0] &= ~0x80;
  }
  return ret;
}

// Generate the Certificate for the RoT Data signing public key.
bool avb_rot_dice_generate_certificate(
    const uint8_t subject_public_key[ED25519_PUBLIC_KEY_LEN],
    const char* cert_subject,
    const uint8_t authority_public_key[ED25519_PUBLIC_KEY_LEN],
    const uint8_t authority_private_key[ED25519_PRIVATE_KEY_LEN],
    size_t certificate_buffer_size,
    uint8_t* certificate,
    size_t* certificate_actual_size) {
  // Subject size should be less then or equal to DICE_ID_SIZE.
  if (avb_strlen(cert_subject) > DICE_ID_SIZE) {
    return false;
  }
  *certificate_actual_size = 0;

  // Derive the Certificate id from authority's public key
  uint8_t authority_id[DICE_ID_SIZE];
  if (!avb_rot_dice_derive_cert_id(authority_public_key,
                                   ED25519_PUBLIC_KEY_LEN,
                                   authority_id,
                                   DICE_ID_SIZE)) {
    return false;
  }

  // Encode the id in hex text string.
  char authority_id_hex[41];
  avb_rot_encode_hex(authority_id,
                     sizeof(authority_id),
                     authority_id_hex,
                     sizeof(authority_id_hex));
  authority_id_hex[sizeof(authority_id_hex) - 1] = '\0';

  // The public key encoded as a COSE_Key structure is embedded in the sig_buf.
  uint8_t encoded_public_key[DICE_MAX_PUBLIC_KEY_SIZE];
  size_t encoded_public_key_size = 0;
  if (!avb_rot_dice_encode_ed25519_COSE_public_key(subject_public_key,
                                                   sizeof(encoded_public_key),
                                                   encoded_public_key,
                                                   &encoded_public_key_size)) {
    return false;
  }

  // Create Cose Sign1 Sig structure.
  uint8_t sig_buf[AVB_ROT_DICE_SIG_STRUCT_MAX_SIZE];
  uint64_t offset = 0;
  avb_memcpy(sig_buf, kDiceCoseSigStructPart, sizeof(kDiceCoseSigStructPart));
  offset += sizeof(kDiceCoseSigStructPart);
  size_t cwt_len = 0;

  // Use certficate buffer as a temporary buffer to hold encoded cwt which will
  // be part of sig structure
  if (!avb_rot_dice_encode_cwt(authority_id_hex,
                               cert_subject,
                               encoded_public_key,
                               encoded_public_key_size,
                               certificate_buffer_size,
                               certificate,
                               &cwt_len)) {
    return false;
  }

  // Copy and encode the encoded cwt as a bytestring in sig_buf
  CborCtx ctx = {
      .buf = sig_buf, .cur = offset, .end = AVB_ROT_DICE_SIG_STRUCT_MAX_SIZE};
  avb_rot_cbor_error(
      avb_rot_cbor_encode_byte_string(&ctx, certificate, 0, cwt_len),
      avb_rot_dice_generate_cert_err);

  // Now sign the Cose Sign1 sig structure.
  uint8_t signature[ED25519_SIGNATURE_LEN];
  if (!avb_ED25519_sign(signature, sig_buf, ctx.cur, authority_private_key)) {
    return false;
  }

  // Re-use the sig buf to hold the encoded cwt which was temporarily stored in
  // the certificate buffer.
  avb_memset(sig_buf, 0, AVB_ROT_DICE_SIG_STRUCT_MAX_SIZE);
  ctx.cur = 0;
  ctx.end = AVB_ROT_DICE_SIG_STRUCT_MAX_SIZE;
  avb_rot_cbor_error(
      avb_rot_cbor_encode_byte_string(&ctx, certificate, 0, cwt_len),
      avb_rot_dice_generate_cert_err);
  cwt_len = ctx.cur;

  // Encode the Cose Sign1 structure.
  // clear the buffer
  avb_memset(certificate, 0, certificate_buffer_size);
  // copy the fixed part
  avb_memcpy(certificate, kCoseSign1StructPart, sizeof(kCoseSign1StructPart));
  offset = sizeof(kCoseSign1StructPart);
  // copy the encoded cwt
  avb_memcpy(certificate + offset, sig_buf, cwt_len);
  offset += cwt_len;
  // encode and copy the signature
  ctx.buf = certificate;
  ctx.cur = offset;
  ctx.end = certificate_buffer_size;
  avb_rot_cbor_error(avb_rot_cbor_encode_byte_string(
                         &ctx, signature, 0, ED25519_SIGNATURE_LEN),
                     avb_rot_dice_generate_cert_err);
  *certificate_actual_size = ctx.cur;
  return true;
avb_rot_dice_generate_cert_err:
  return false;
}

// Generate the Signed RoT data and RoT Data signing key certificate.
AvbSlotVerifyResult avb_rot_generate_rot_data(AvbOps* ops,
                                              AvbSlotVerifyData* slotData) {
  AvbSlotVerifyResult ret = AVB_SLOT_VERIFY_RESULT_OK;
  // If the RoT is not supported then return silently.
  if (ops->generate_true_random == NULL ||
      ops->sign_key_with_cdi_attest == NULL || ops->read_boot_nonce == NULL ||
      ops->read_vb_flow_data == NULL) {
    avb_debug("RoT related ops function Pointers are not initialized\n");
    return ret;
  }

  uint64_t bootNonce = 0;
  vb_state_t state = verified;
  bool bootLoaderLocked = false;
  bool userEnabledRot = false;
  bool deviceEioMode = false;
  uint32_t osVersion = 0;
  uint32_t bootPatchLvl = 0;
  uint32_t vendorPatchLvl = 0;
  uint32_t osPatchLvl = 0;
  uint8_t* rotPublicKey = avb_calloc(ED25519_PUBLIC_KEY_LEN);
  uint8_t* rotPrivateKey = avb_calloc(ED25519_PRIVATE_KEY_LEN);
  uint8_t* seed = avb_calloc(32);
  uint8_t* vbmeta_digest = avb_calloc(AVB_SHA256_DIGEST_SIZE);
  AvbSHA256Ctx* sha256_ctx = avb_calloc(sizeof(AvbSHA256Ctx));
  uint8_t* rotData = avb_calloc(AVB_ROT_MAX_DATA_SIZE);
  uint8_t* signature = avb_calloc(ED25519_SIGNATURE_LEN);
  const char* certificateSubject = "AVB_ROT";
  uint8_t* signedRotData = avb_calloc(AVB_ROT_MAX_DATA_SIZE);
  uint8_t* rotSigningKeyCert = avb_calloc(ROT_SIGNING_KEY_CERT_SIZE);

  if (rotPublicKey == NULL || rotPrivateKey == NULL || seed == NULL ||
      vbmeta_digest == NULL || sha256_ctx == NULL || rotData == NULL ||
      signedRotData == NULL || rotSigningKeyCert == NULL || signature == NULL) {
    avb_debug("RoT out of memory\n");
    ret = AVB_SLOT_VERIFY_RESULT_ERROR_OOM;
    goto generateRotDataErr;
  }

  // Read boot parameters
  if (ops->read_boot_nonce(ops, &bootNonce) != AVB_IO_RESULT_OK ||
      ops->read_vb_flow_data(
          ops, &bootLoaderLocked, &userEnabledRot, &deviceEioMode) !=
          AVB_IO_RESULT_OK) {
    avb_debug("Error executing read_rot_data operation\n");
    ret = AVB_SLOT_VERIFY_RESULT_ERROR_IO;
    goto generateRotDataErr;
  }

  // determine the verified boot state according to avb boot flow
  // specification. Note that at this stage images have been already
  // verified to be valid, so state is verified.
  if (deviceEioMode) {
    // However, if deviceEioMode is enabled then state is failed.
    state = failed;  // red
  } else if (!bootLoaderLocked) {
    // If bootloader is not locked and deviceEioMode is not
    // enabled then state is unverified
    state = unverified;  // orange
  } else if (userEnabledRot) {
    // If bootloader is locked and user has enabkled Rot then state
    // is self_signed.
    state = self_signed;  // yellow
  }

  // Calculate vbmeta digest
  avb_slot_verify_data_calculate_vbmeta_digest(
      slotData, AVB_DIGEST_TYPE_SHA256, vbmeta_digest);

  // Calculate VBKey0 digest
  AvbVBMetaImageHeader imgHeader;
  avb_vbmeta_image_header_to_host_byte_order(
      (const AvbVBMetaImageHeader*)(slotData->vbmeta_images[0].vbmeta_data),
      &imgHeader);
  uint8_t* pk_start =
      slotData->vbmeta_images[0].vbmeta_data + sizeof(AvbVBMetaImageHeader) +
      imgHeader.authentication_data_block_size + imgHeader.public_key_offset;
  uint64_t pk_size = imgHeader.public_key_size;
  avb_sha256_init(sha256_ctx);
  avb_sha256_update(sha256_ctx, pk_start, pk_size);
  uint8_t* vbKey0Digest = avb_sha256_final(sha256_ctx);
  // extract rot properties from vb meta
  if (!extract_rot_relevant_data(
          slotData, &osVersion, &osPatchLvl, &vendorPatchLvl, &bootPatchLvl)) {
    avb_error("Extract rot_data operation failed\n");
    ret = AVB_SLOT_VERIFY_RESULT_ERROR_IO;
    goto generateRotDataErr;
  }
  // Encode rot data
  int64_t rotDataLen = avb_rot_cbor_encode_rot_data(bootNonce,
                                                    vbKey0Digest,
                                                    bootLoaderLocked,
                                                    state,
                                                    vbmeta_digest,
                                                    osVersion,
                                                    osPatchLvl,
                                                    vendorPatchLvl,
                                                    bootPatchLvl,
                                                    rotData);

  // Encode rot signing input
  int64_t signingInputLen =
      avb_rot_cbor_encode_signing_input(rotData, rotDataLen, signedRotData);

  // Generate keypairs
  if (ops->generate_true_random(ops, 32, seed) != AVB_IO_RESULT_OK) {
    ret = AVB_SLOT_VERIFY_RESULT_ERROR_IO;
    avb_debug("Error executing generate_true_random operation\n");
    goto generateRotDataErr;
  }

  avb_ED25519_keypair_from_seed(rotPublicKey, rotPrivateKey, seed);
  avb_memset(seed, 0, 32);

  // Sign the signing data
  if (avb_ED25519_sign(
          signature, signedRotData, signingInputLen, rotPrivateKey) != 1) {
    ret = AVB_SLOT_VERIFY_RESULT_ERROR_IO;
    avb_debug("Error executing avb_ED25519_sign operation\n");
    goto generateRotDataErr;
  }
  avb_memset(rotPrivateKey, 0, ED25519_PRIVATE_KEY_LEN);
  avb_memset(signedRotData, 0, signingInputLen);

  // Generate DICE attested certificate
  size_t actualCertLen = 0;
  if (ops->sign_key_with_cdi_attest(ops,
                                    rotPublicKey,
                                    ED25519_PUBLIC_KEY_LEN,
                                    certificateSubject,
                                    ROT_SIGNING_KEY_CERT_SIZE,
                                    rotSigningKeyCert,
                                    &actualCertLen) != AVB_IO_RESULT_OK) {
    ret = AVB_SLOT_VERIFY_RESULT_ERROR_IO;
    avb_debug("Error executing sign_key_with_cdi_attest operation\n");
    goto generateRotDataErr;
  }
  avb_memset(rotPublicKey, 0, ED25519_PUBLIC_KEY_LEN);

  // Encode signed rot data
  rotDataLen = avb_rot_cbor_encode_signed_rot_data(
      rotData, rotDataLen, signature, signedRotData);

  ret = avb_rot_append_options(
      slotData, signedRotData, rotDataLen, rotSigningKeyCert, actualCertLen);

generateRotDataErr:
  if (seed != NULL) {
    avb_free(seed);
  }
  if (rotPrivateKey != NULL) {
    avb_free(rotPrivateKey);
  }
  if (rotPublicKey != NULL) {
    avb_free(rotPublicKey);
  }
  if (vbmeta_digest != NULL) {
    avb_free(vbmeta_digest);
  }
  if (sha256_ctx != NULL) {
    avb_free(sha256_ctx);
  }
  if (rotData != NULL) {
    avb_free(rotData);
  }
  if (signature != NULL) {
    avb_free(signature);
  }
  if (signedRotData != NULL) {
    avb_free(signedRotData);
  }
  if (rotSigningKeyCert != NULL) {
    avb_free(rotSigningKeyCert);
  }

  return ret;
}
