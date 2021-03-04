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

#include <dice/cbor_cert_op.h>
#include <dice/cbor_writer.h>
#include <dice/dice.h>
#include <libavb/avb_ed25519.h>
#include <libavb/avb_hkdf.h>
#include <libavb/avb_sha.h>
#include <libavb/libavb.h>

#include "libavb_open_dice.h"

// TODO: make these less arbitrary
#define MAX_CERT_SIZE 2560
#define MAX_CONFIG_SIZE 192

static void open_dice_clear_memory_op(const DiceOps* dice_ops,
                                      size_t size,
                                      void* address) {
  AvbOpenDiceOps* ops = (AvbOpenDiceOps*)dice_ops->context;

  ops->clear_memory(ops, size, address);
}

static DiceResult open_dice_hash_op(const DiceOps* ops_not_used,
                                    const uint8_t* input,
                                    size_t input_size,
                                    uint8_t output[DICE_HASH_SIZE]) {
  AvbSHA512Ctx sha512_ctx;

  (void)ops_not_used;
  avb_sha512_init(&sha512_ctx);
  avb_sha512_update(&sha512_ctx, input, input_size);
  avb_memcpy(output, avb_sha512_final(&sha512_ctx), DICE_HASH_SIZE);
  return kDiceResultOk;
}

static DiceResult open_dice_kdf_op(const DiceOps* ops_not_used,
                                   size_t length,
                                   const uint8_t* ikm,
                                   size_t ikm_size,
                                   const uint8_t* salt,
                                   size_t salt_size,
                                   const uint8_t* info,
                                   size_t info_size,
                                   uint8_t* output) {
  (void)ops_not_used;
  if (!avb_hkdf_sha512(
          output, length, ikm, ikm_size, salt, salt_size, info, info_size)) {
    return kDiceResultPlatformError;
  }
  return kDiceResultOk;
}

static DiceResult open_dice_keypair_from_seed_op(
    const DiceOps* ops_not_used,
    const uint8_t seed[DICE_PRIVATE_KEY_SEED_SIZE],
    uint8_t public_key[DICE_PUBLIC_KEY_MAX_SIZE],
    size_t* public_key_size,
    uint8_t private_key[DICE_PRIVATE_KEY_MAX_SIZE],
    size_t* private_key_size) {
  (void)ops_not_used;
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

static DiceResult open_dice_sign_op(const DiceOps* ops_not_used,
                                    const uint8_t* message,
                                    size_t message_size,
                                    const uint8_t* private_key,
                                    size_t private_key_size,
                                    size_t signature_size,
                                    uint8_t* signature) {
  (void)ops_not_used;
  if (private_key_size != 64 || signature_size != 64) {
    return kDiceResultPlatformError;
  }
  if (!avb_ed25519_sign(signature, message, message_size, private_key)) {
    return kDiceResultPlatformError;
  }
  return kDiceResultOk;
}

static DiceResult open_dice_verify_op(const DiceOps* ops_not_used,
                                      const uint8_t* message,
                                      size_t message_size,
                                      const uint8_t* signature,
                                      size_t signature_size,
                                      const uint8_t* public_key,
                                      size_t public_key_size) {
  (void)ops_not_used;
  if (public_key_size != 32 || signature_size != 64) {
    return kDiceResultPlatformError;
  }
  if (!avb_ed25519_verify(message, message_size, signature, public_key)) {
    return kDiceResultPlatformError;
  }
  return kDiceResultOk;
}

static void write_config_descriptor(
    const char* component_name,
    bool resettable,
    uint64_t rollback_index,
    uint8_t public_key_hash[AVB_SHA512_DIGEST_SIZE],
    struct CborOut* out) {
  size_t num_pairs = resettable ? 2 : 1;

  CborWriteMap(num_pairs, out);
  // Add the component name.
  CborWriteInt(AVB_OPEN_DICE_CONFIG_COMPONENT_NAME_LABEL, out);
  CborWriteTstr(component_name, out);

  // TODO: should this capture chained partition versions or how can you
  //       reconstruct the vbmeta digest?
  CborWriteInt(AVB_OPEN_DICE_CONFIG_VERSION_LABEL, out);
  CborWriteInt(rollback_index, out);
  // TODO: CborWriteUint(rollback_index, out);

  if (resettable) {
    // Mark the key as changing on factory reset.
    CborWriteInt(AVB_OPEN_DICE_CONFIG_RESETTABLE_LABEL, out);
    CborWriteNull(out);
  }

  // Add has of the public key of the top-level vbmeta struct.
  CborWriteInt(AVB_OPEN_DICE_CONFIG_ACTIVE_AUTHORITY_LABEL, out);
  CborWriteBstr(AVB_SHA512_DIGEST_SIZE, public_key_hash, out);
}

static AvbOpenDiceResult generate_config_descriptor(
    const char* component_name,
    bool resettable,
    const AvbSlotVerifyData* slot_data,
    void** config_descriptor,
    size_t* config_descriptor_size) {
  AvbSHA512Ctx sha512_ctx;
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
  avb_sha512_init(&sha512_ctx);
  avb_sha512_update(&sha512_ctx, public_key, h.public_key_size);
  public_key_hash = avb_sha512_final(&sha512_ctx);

  buffer = avb_malloc(MAX_CONFIG_SIZE);
  if (!buffer) {
    return AVB_OPEN_DICE_RESULT_ERROR_OOM;
  }

  CborOutInit(buffer, MAX_CONFIG_SIZE, &out);
  write_config_descriptor(
      component_name, h.rollback_index, resettable, public_key_hash, &out);
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
    AvbOpenDiceMode mode,
    bool resettable,
    const uint8_t hidden[AVB_OPEN_DICE_HIDDEN_SIZE],
    const uint8_t authority_hash[AVB_SHA512_DIGEST_SIZE],
    const AvbSlotVerifyData* slot_data,
    AvbOpenDiceData** out_data) {
  void* config_descriptor = NULL;
  DiceResult result;
  AvbOpenDiceResult ret;

  // Check the AVB interface matches that of Open Dice.
  avb_assert(AVB_OPEN_DICE_HIDDEN_SIZE == DICE_HIDDEN_SIZE);
  avb_assert(AVB_OPEN_DICE_CDI_SIZE == DICE_CDI_SIZE);
  avb_assert(AVB_SHA512_DIGEST_SIZE == DICE_HASH_SIZE);

  DiceOps dice_ops = {
      .context = ops,
      .hash = open_dice_hash_op,
      .kdf = open_dice_kdf_op,
      .keypair_from_seed = open_dice_keypair_from_seed_op,
      .sign = open_dice_sign_op,
      .verify = open_dice_verify_op,
      .generate_certificate = DiceGenerateCborCertificateOp,
      .clear_memory = open_dice_clear_memory_op,
  };

  DiceInputValues input_values = {
      .config_type = kDiceConfigTypeDescriptor,
      .mode =
          mode == AVB_OPEN_DICE_MODE_NORMAL ? kDiceModeNormal : kDiceModeDebug,
  };

  avb_slot_verify_data_calculate_vbmeta_digest(
      slot_data, AVB_DIGEST_TYPE_SHA256, input_values.code_hash);
  // TODO: zero like this or hash it again to make it 512 bytes?
  avb_memset(&input_values.code_hash[AVB_SHA256_DIGEST_SIZE],
             0,
             DICE_HASH_SIZE - AVB_SHA256_DIGEST_SIZE);

  ret = generate_config_descriptor("AVB",
                                   resettable,
                                   slot_data,
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

  avb_memcpy(&input_values.hidden, &hidden, DICE_HIDDEN_SIZE);
  avb_memcpy(
      input_values.authority_hash, authority_hash, AVB_SHA256_DIGEST_SIZE);

  result = DiceMainFlow(&dice_ops,
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
