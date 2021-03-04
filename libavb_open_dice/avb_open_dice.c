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

#include <dice/cbor_writer.h>
#include <dice/dice.h>
#include <dice/ops.h>
#include <libavb/avb_ed25519.h>
#include <libavb/avb_hkdf.h>
#include <libavb/avb_sha.h>
#include <libavb/libavb.h>

#include "libavb_open_dice.h"

#define MAX_CERT_SIZE 768
#define MAX_CONFIG_SIZE 128

#define AVB_OPEN_DICE_CONFIG_COMPONENT_NAME_LABEL -70002
#define AVB_OPEN_DICE_CONFIG_COMPONENT_VERSION_LABEL -70003
#define AVB_OPEN_DICE_CONFIG_RESETTABLE_LABEL -70004
#define AVB_OPEN_DICE_CONFIG_VERIFICATION_KEY_LABEL -70004

void DiceClearMemory(void* context, size_t size, void* address) {
  AvbOpenDiceOps* ops = (AvbOpenDiceOps*)context;

  ops->clear_memory(ops, size, address);
}

DiceResult DiceHash(void* context,
                    const uint8_t* input,
                    size_t input_size,
                    uint8_t output[DICE_HASH_SIZE]) {
  AvbSHA512Ctx sha512_ctx;

  (void)context;
  avb_sha512_init(&sha512_ctx);
  avb_sha512_update(&sha512_ctx, input, input_size);
  avb_memcpy(output, avb_sha512_final(&sha512_ctx), DICE_HASH_SIZE);
  return kDiceResultOk;
}

DiceResult DiceKdf(void* context,
                   size_t length,
                   const uint8_t* ikm,
                   size_t ikm_size,
                   const uint8_t* salt,
                   size_t salt_size,
                   const uint8_t* info,
                   size_t info_size,
                   uint8_t* output) {
  (void)context;
  if (!avb_hkdf_sha512(
          output, length, ikm, ikm_size, salt, salt_size, info, info_size)) {
    return kDiceResultPlatformError;
  }
  return kDiceResultOk;
}

DiceResult DiceKeypairFromSeed(void* context,
                               const uint8_t seed[DICE_PRIVATE_KEY_SEED_SIZE],
                               uint8_t public_key[DICE_PUBLIC_KEY_MAX_SIZE],
                               size_t* public_key_size,
                               uint8_t private_key[DICE_PRIVATE_KEY_MAX_SIZE],
                               size_t* private_key_size) {
  (void)context;
#if DICE_PRIVATE_KEY_SEED_SIZE != 32
#error "Private key seed is expected to be 32 bytes."
#endif
#if DICE_PUBLIC_KEY_MAX_SIZE < 32
#error "Ed25519 needs 32 bytes to store the public key."
#endif
#if DICE_PRIVATE_KEY_MAX_SIZE < 64
#error "This Ed25519 implementation needs 64 bytes for the private key."
#endif
  avb_ed25519_keypair_from_seed(public_key, private_key, seed);
  *public_key_size = 32;
  *private_key_size = 64;
  return kDiceResultOk;
}

DiceResult DiceSign(void* context,
                    const uint8_t* message,
                    size_t message_size,
                    const uint8_t* private_key,
                    size_t private_key_size,
                    size_t signature_size,
                    uint8_t* signature) {
  (void)context;
  if (private_key_size != 64 || signature_size != 64) {
    return kDiceResultPlatformError;
  }
  if (!avb_ed25519_sign(signature, message, message_size, private_key)) {
    return kDiceResultPlatformError;
  }
  return kDiceResultOk;
}

DiceResult DiceVerify(void* context,
                      const uint8_t* message,
                      size_t message_size,
                      const uint8_t* signature,
                      size_t signature_size,
                      const uint8_t* public_key,
                      size_t public_key_size) {
  (void)context;
  if (public_key_size != 32 || signature_size != 64) {
    return kDiceResultPlatformError;
  }
  if (!avb_ed25519_verify(message, message_size, signature, public_key)) {
    return kDiceResultPlatformError;
  }
  return kDiceResultOk;
}

/* AvbConfig = {
 *   -70002: str,                      // Component name
 *   -70003: int,                      // Component version
 *   -70004: null,                     // Resettable
 *   -70005: bstr .cbor [              // Signer
 *     boot_state: 0 / 1 / 2 / 3,
 *     boot_key: bstr .size 32,
 *   ],
 * }
 */
static void write_config_descriptor(
    uint64_t rollback_index,
    AvbOpenDiceBootState boot_state,
    uint8_t public_key_hash[AVB_SHA256_DIGEST_SIZE],
    struct CborOut* out) {
  uint8_t authority_buffer[1 + 1 + 2 + AVB_SHA256_DIGEST_SIZE];
  struct CborOut authority_out;

  CborWriteMap(4, out);
  // Add the component name.
  CborWriteInt(AVB_OPEN_DICE_CONFIG_COMPONENT_NAME_LABEL, out);
  CborWriteTstr("AVB", out);
  // Add the version of the top-level vbmeta struct.
  CborWriteInt(AVB_OPEN_DICE_CONFIG_COMPONENT_VERSION_LABEL, out);
  CborWriteUint(rollback_index, out);
  // Mark the key as changing on factory reset.
  CborWriteInt(AVB_OPEN_DICE_CONFIG_RESETTABLE_LABEL, out);
  CborWriteNull(out);
  // Add the verification key of the top-level vbmeta struct.
  CborWriteInt(AVB_OPEN_DICE_CONFIG_VERIFICATION_KEY_LABEL, out);
  CborOutInit(authority_buffer, sizeof(authority_buffer), &authority_out);
  CborWriteArray(2, &authority_out);
  CborWriteInt(boot_state, &authority_out);
  CborWriteBstr(AVB_SHA256_DIGEST_SIZE, public_key_hash, &authority_out);
  avb_assert(!CborOutOverflowed(&authority_out));
  avb_assert(CborOutSize(&authority_out) == sizeof(authority_buffer));
  CborWriteBstr(sizeof(authority_buffer), authority_buffer, out);
}

static AvbOpenDiceResult generate_config_descriptor(
    const AvbSlotVerifyData* slot_data,
    AvbOpenDiceBootState boot_state,
    void** config_descriptor,
    size_t* config_descriptor_size) {
  AvbSHA256Ctx sha256_ctx;
  AvbVBMetaImageHeader h;
  uint8_t* vbmeta_data;
  uint8_t* public_key;
  uint8_t* public_key_hash;
  struct CborOut out;
  void* buffer;

  vbmeta_data = slot_data->vbmeta_images[0].vbmeta_data;
  avb_vbmeta_image_header_to_host_byte_order(
      (const AvbVBMetaImageHeader*)vbmeta_data, &h);
  public_key = vbmeta_data + sizeof(h) + h.authentication_data_block_size +
               h.public_key_offset;
  avb_sha256_init(&sha256_ctx);
  avb_sha256_update(&sha256_ctx, public_key, h.public_key_size);
  public_key_hash = avb_sha256_final(&sha256_ctx);

  buffer = avb_malloc(MAX_CONFIG_SIZE);
  if (!buffer) {
    return AVB_OPEN_DICE_RESULT_ERROR_OOM;
  }

  CborOutInit(buffer, MAX_CONFIG_SIZE, &out);
  write_config_descriptor(h.rollback_index, boot_state, public_key_hash, &out);
  if (CborOutOverflowed(&out)) {
    avb_free(buffer);
    return AVB_OPEN_DICE_RESULT_ERROR_OOM;
  }

  *config_descriptor = buffer;
  *config_descriptor_size = CborOutSize(&out);
  return AVB_OPEN_DICE_RESULT_OK;
}

void avb_open_dice_data_free(AvbOpenDiceOps* ops, AvbOpenDiceData* data) {
  if (!data) {
    return;
  }

  ops->clear_memory(ops, DICE_CDI_SIZE, data->cdi_attest);
  ops->clear_memory(ops, DICE_CDI_SIZE, data->cdi_seal);

  if (data->cert) {
    avb_free(data->cert);
  }

  avb_free(data);
}

AvbOpenDiceResult avb_open_dice_generate(
    AvbOpenDiceOps* ops,
    const uint8_t cdi_attest[AVB_OPEN_DICE_CDI_SIZE],
    const uint8_t cdi_seal[AVB_OPEN_DICE_CDI_SIZE],
    AvbOpenDiceBootState boot_state,
    const uint8_t authority_hash[AVB_SHA256_DIGEST_SIZE],
    const uint8_t secret[AVB_OPEN_DICE_SECRET_SIZE],
    const AvbSlotVerifyData* slot_data,
    AvbOpenDiceData** out_data) {
  void* config_descriptor = NULL;
  DiceResult result;
  AvbIOResult io_result;
  AvbOpenDiceResult ret;
  bool unlocked;

  // Check the AVB interface matches that of Open Dice.
  avb_assert(AVB_OPEN_DICE_SECRET_SIZE == DICE_HIDDEN_SIZE);
  avb_assert(AVB_OPEN_DICE_CDI_SIZE == DICE_CDI_SIZE);
  avb_assert(AVB_SHA512_DIGEST_SIZE == DICE_HASH_SIZE);

  io_result = ops->ops->read_is_device_unlocked(ops->ops, &unlocked);
  if (io_result == AVB_IO_RESULT_ERROR_OOM) {
    ret = AVB_OPEN_DICE_RESULT_ERROR_OOM;
    goto out;
  } else if (io_result != AVB_IO_RESULT_OK) {
    ret = AVB_OPEN_DICE_RESULT_ERROR_IO;
    goto out;
  }

  DiceInputValues input_values = {
      .config_type = kDiceConfigTypeDescriptor,
      .mode = unlocked ? kDiceModeDebug : kDiceModeNormal,
  };

  // Use a zero-padded SHA256 digest to match the algorithm commonly
  // recommended by Android.
  avb_slot_verify_data_calculate_vbmeta_digest(
      slot_data, AVB_DIGEST_TYPE_SHA256, input_values.code_hash);
  avb_memset(&input_values.code_hash[AVB_SHA256_DIGEST_SIZE],
             0,
             DICE_HASH_SIZE - AVB_SHA256_DIGEST_SIZE);

  ret = generate_config_descriptor(slot_data,
                                   boot_state,
                                   &config_descriptor,
                                   &input_values.config_descriptor_size);
  input_values.config_descriptor = config_descriptor;
  if (ret != AVB_OPEN_DICE_RESULT_OK) {
    goto out;
  }

  AvbOpenDiceData* data = avb_malloc(sizeof(AvbOpenDiceData));
  if (!data) {
    ret = AVB_OPEN_DICE_RESULT_ERROR_OOM;
    goto out;
  }

  data->cert_size = MAX_CERT_SIZE;
  data->cert = avb_malloc(data->cert_size);
  if (!data->cert) {
    ret = AVB_OPEN_DICE_RESULT_ERROR_OOM;
    goto fail;
  }

  avb_memcpy(&input_values.hidden, &secret, DICE_HIDDEN_SIZE);
  avb_memcpy(
      input_values.authority_hash, authority_hash, AVB_SHA256_DIGEST_SIZE);

  result = DiceMainFlow(ops,
                        cdi_attest,
                        cdi_seal,
                        &input_values,
                        data->cert_size,
                        data->cert,
                        &data->cert_size,
                        data->cdi_attest,
                        data->cdi_seal);
  if (result != kDiceResultOk) {
    ret = AVB_OPEN_DICE_RESULT_ERROR_CERTIFICATE;
    goto fail;
  }

  *out_data = data;
  ret = AVB_OPEN_DICE_RESULT_OK;
  goto out;

fail:
  avb_open_dice_data_free(ops, data);

out:
  if (config_descriptor) {
    avb_free(config_descriptor);
  }
  ops->clear_memory(ops, DICE_HIDDEN_SIZE, &input_values.hidden);
  return ret;
}
