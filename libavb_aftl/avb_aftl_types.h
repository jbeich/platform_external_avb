/*
 * Copyright (C) 2020 The Android Open Source Project
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

#ifdef AVB_INSIDE_LIBAVB_AFTL_H
#error "You can't include avb_aftl_types.h in the public header libavb_aftl.h."
#endif

#ifndef AVB_COMPILATION
#error "Never include this file, it may only be used from internal avb code."
#endif

#ifndef AVB_AFTL_TYPES_H_
#define AVB_AFTL_TYPES_H_

#include <libavb/libavb.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Hash and signature size supported. Hash is SHA256, signature is RSA4096. */
#define AVB_AFTL_HASH_SIZE 32ul
#define AVB_AFTL_SIGNATURE_SIZE 512ul
/* Raw key size used for signature validation. */
#define AVB_AFTL_PUB_KEY_SIZE 1032ul

/* Data structure containing AFTL header information. */
typedef struct AftlIcpHeader {
  uint32_t magic;
  uint32_t required_icp_version_major;
  uint32_t required_icp_version_minor;
  uint32_t aftl_descriptor_size; /* Total size of the AftlDescriptor. */
  uint16_t icp_count;
} AVB_ATTR_PACKED AftlIcpHeader;

/* Data structure containing a Trillian LogRootDescriptor, from
   https://github.com/google/trillian/blob/master/trillian.proto#L255
   The log_root_signature is calculated over this structure. */
typedef struct TrillianLogRootDescriptor {
  uint16_t version;
  uint64_t tree_size;
  uint8_t root_hash_size;
  uint8_t* root_hash;
  uint64_t timestamp;
  uint64_t revision;
  uint16_t metadata_size;
  uint8_t* metadata;
} TrillianLogRootDescriptor;

#define AVB_AFTL_MAX_METADATA_SIZE (4096)
#define AVB_AFTL_MIN_TLRD_SIZE                                     \
  (sizeof(uint16_t) * 2 + sizeof(uint64_t) * 3 + sizeof(uint8_t) + \
   AVB_AFTL_HASH_SIZE)
#define AVB_AFTL_MAX_TLRD_SIZE (65536 - sizeof(AftlIcpHeader))
/* Data structure containing the firmware image info stored in the
   transparency log. This is defined in
   https://android.googlesource.com/platform/external/avb/+/master/proto/aftl.proto
 */
typedef struct FirmwareInfo {
  uint32_t vbmeta_hash_size;
  uint8_t* vbmeta_hash;
  uint32_t version_incremental_size;
  uint8_t* version_incremental;
  uint32_t platform_key_size;
  uint8_t* platform_key;
  uint32_t manufacturer_key_hash_size;
  uint8_t* manufacturer_key_hash;
  uint32_t description_size;
  uint8_t* description;
} FirmwareInfo;

#define AVB_AFTL_MAX_VERSION_INCREMENTAL_SIZE (256)
#define AVB_AFTL_MIN_FW_INFO_SIZE \
  (AVB_AFTL_HASH_SIZE * 2 + AVB_AFTL_PUB_KEY_SIZE)
#define AVB_AFTL_MAX_FW_INFO_SIZE (65536 - sizeof(AftlIcpHeader))

/* Data structure containing AFTL inclusion proof data from a single
   transparency log. */
typedef struct AftlIcpEntry {
  uint32_t log_url_size;
  uint64_t leaf_index;
  uint32_t log_root_descriptor_size;
  uint32_t fw_info_leaf_size;
  uint32_t log_root_sig_size;
  uint8_t proof_hash_count;
  uint32_t inc_proof_size;
  uint8_t* log_url;
  TrillianLogRootDescriptor log_root_descriptor;
  FirmwareInfo fw_info_leaf;
  uint8_t* log_root_signature;
  uint8_t proofs[/*proof_hash_count*/][AVB_AFTL_HASH_SIZE];
} AftlIcpEntry;

#define AVB_AFTL_MIN_AFTL_ICP_ENTRY_SIZE                       \
  (sizeof(uint32_t) * 5 + sizeof(uint64_t) + sizeof(uint8_t) + \
   AVB_AFTL_MIN_TLRD_SIZE + AVB_AFTL_MIN_FW_INFO_SIZE +        \
   AVB_AFTL_SIGNATURE_SIZE)
#define AVB_AFTL_MAX_AFTL_ICP_ENTRY_SIZE (65536 - sizeof(AftlIcpHeader))
#define AVB_AFTL_MAX_URL_SIZE 2048

/* Main data structure for an AFTL descriptor. */
typedef struct AftlDescriptor {
  AftlIcpHeader header;
  AftlIcpEntry** entries;
} AVB_ATTR_PACKED AftlDescriptor;
/* Limit AftlDescriptor size to 64KB for now. */
#define AVB_AFTL_MAX_AFTL_DESCRIPTOR_SIZE 65536

#ifdef __cplusplus
}
#endif

#endif /* AVB_AFTL_TYPES_H_ */
