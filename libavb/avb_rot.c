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
#include "avb_rot_cbor.h"
#include "avb_sha.h"
#include "avb_sysdeps.h"
#include "avb_util.h"

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

// SHA Block Sizes
#define AVB_ROT_SHA512_BLOCK_SIZE 128
#define AVB_ROT_SHA256_BLOCK_SIZE 64

#define AVB_ROT_ERROR -1

// Enumeration of verified boot state
typedef enum { verified, self_signed, unverified, failed } vb_state_t;

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

// Generate the Signed RoT data and RoT Data signing key certificate.
AvbSlotVerifyResult avb_rot_generate_rot_data(AvbOps* ops,
                                              AvbSlotVerifyData* slotData) {
  AvbSlotVerifyResult ret = AVB_SLOT_VERIFY_RESULT_OK;
  // If the RoT is not supported then return silently.
  if (ops->generate_true_random == NULL ||
      ops->sign_key_with_cdi_attest == NULL || ops->read_boot_nonce == NULL ||
      ops->read_vb_flow_data == NULL ||
      ops->read_dice_cert_chain_size == NULL ||
      ops->read_dice_cert_chain == NULL) {
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
  uint8_t* rotSigningKeyCert = avb_calloc(AVB_ROT_MAX_SIGNING_KEY_CERT_SIZE);
  uint8_t* rotDiceCertChain = NULL;

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
                                    AVB_ROT_MAX_SIGNING_KEY_CERT_SIZE,
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

  // read the dice cert chain
  size_t dice_cert_chain_size = 0;
  if (ops->read_dice_cert_chain_size(ops, &dice_cert_chain_size) !=
      AVB_IO_RESULT_OK) {
    ret = AVB_SLOT_VERIFY_RESULT_ERROR_IO;
    avb_debug("Error executing get_dice_cert_chain_size operation\n");
    goto generateRotDataErr;
  }
  rotDiceCertChain = avb_calloc(dice_cert_chain_size);
  if (rotDiceCertChain == NULL) {
    ret = AVB_SLOT_VERIFY_RESULT_ERROR_IO;
    avb_debug("Error allocating memory for dice cert chain\n");
    goto generateRotDataErr;
  }
  if (ops->read_dice_cert_chain(ops, dice_cert_chain_size, rotDiceCertChain) !=
      AVB_IO_RESULT_OK) {
    ret = AVB_SLOT_VERIFY_RESULT_ERROR_IO;
    avb_debug("Error executing get_dice_cert_chain operation\n");
    goto generateRotDataErr;
  }
  ret = avb_rot_append_options(slotData,
                               signedRotData,
                               rotDataLen,
                               rotSigningKeyCert,
                               actualCertLen,
                               rotDiceCertChain,
                               dice_cert_chain_size);

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
  if (rotDiceCertChain != NULL) {
    avb_free(rotDiceCertChain);
  }
  return ret;
}
