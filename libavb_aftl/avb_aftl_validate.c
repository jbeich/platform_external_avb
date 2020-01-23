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

#include <libavb/avb_crypto.h>
#include <libavb/avb_rsa.h>
#include <libavb/avb_sha.h>
#include <libavb/avb_util.h>

#include "avb_aftl_types.h"
#include "avb_aftl_validate.h"

/* Verifies that the logged VBMeta hash matches the one on device. */
bool aftl_verify_vbmeta_hash(uint8_t* vbmeta,
                             size_t vbmeta_size,
                             AftlIcpEntry* icp_entry) {
  uint8_t vbmeta_hash[AFTL_HASH_SIZE];
  uint8_t leaf_vbmeta_hash[AFTL_HASH_SIZE];

  aftl_sha256(vbmeta, vbmeta_size, vbmeta_hash);
  // The VBMeta hash is stored in the first AFTL_HASH_SIZE bytes of the leaf.
  avb_memcpy(leaf_vbmeta_hash, icp_entry->fw_info_leaf, AFTL_HASH_SIZE);

  // Check if the calculated VBMeta hash matches the stored one.
  return (avb_memcmp(vbmeta_hash, leaf_vbmeta_hash, AFTL_HASH_SIZE) == 0);
}

/* Verifies the Merkle tree root hash. */
bool aftl_verify_icp_root_hash(AftlIcpEntry* icp_entry) {
  uint8_t leaf_hash[AFTL_HASH_SIZE];
  uint8_t result_hash[AFTL_HASH_SIZE];

  /* Calculate the RFC 6962 hash of the seed entry. */
  rfc6962_hash_leaf(
      icp_entry->fw_info_leaf, icp_entry->fw_info_leaf_size, leaf_hash);
  /* Calculate the Merkle tree's root hash. */
  root_from_icp(icp_entry->leaf_index,
                icp_entry->log_root_descriptor.tree_size,
                icp_entry->proofs,
                icp_entry->proof_hash_count,
                leaf_hash,
                AFTL_HASH_SIZE,
                result_hash);
  /* Check if the calculated root hash matches the stored one. */
  return (avb_memcmp(result_hash,
                     icp_entry->log_root_descriptor.root_hash,
                     AFTL_HASH_SIZE) == 0);
}

/* Verifies the log root signature for the transparency log submission. */
bool aftl_verify_entry_signature(const uint8_t* key,
                                 size_t key_num_bytes,
                                 AftlIcpEntry* icp_entry) {
  uint8_t* sig;
  size_t sig_num_bytes;
  uint8_t log_root_hash[AFTL_HASH_SIZE];
  size_t log_root_hash_num_bytes;
  const AvbAlgorithmData* algorithm_data;

  /* Extract the log root signature from the AftlIcpEntry. */
  sig = icp_entry->log_root_signature;
  sig_num_bytes = icp_entry->log_root_sig_size;
  log_root_hash_num_bytes = AFTL_HASH_SIZE;
  /* Calculate the SHA256 of the TrillianLogRootDescriptor. */
  hash_log_root_descriptor(icp_entry, log_root_hash);

  /* algorithm_data is used to calculate the padding for signature verification.
   */
  algorithm_data = avb_get_algorithm_data(AVB_ALGORITHM_TYPE_SHA256_RSA4096);
  return avb_rsa_verify(key,
                        key_num_bytes,
                        sig,
                        sig_num_bytes,
                        log_root_hash,
                        log_root_hash_num_bytes,
                        algorithm_data->padding,
                        algorithm_data->padding_len);
}

/* Performs a SHA256 hash operation on data. */
void aftl_sha256(uint8_t* data, uint64_t length, uint8_t hash[AFTL_HASH_SIZE]) {
  AvbSHA256Ctx context;
  uint8_t* tmp;

  avb_sha256_init(&context);
  avb_sha256_update(&context, data, length);
  tmp = avb_sha256_final(&context);
  avb_memcpy(hash, tmp, AFTL_HASH_SIZE);
}

/* Calculates a SHA256 hash of the TrillianLogRootDescriptor in icp_entry. */
void hash_log_root_descriptor(AftlIcpEntry* icp_entry, uint8_t* hash) {
  uint8_t* buffer;
  size_t descriptor_size;

  buffer = (uint8_t*)avb_malloc(descriptor_size);
  /* Copy the descriptor data (aside from metadata) */
  avb_memcpy(buffer,
             &(icp_entry->log_root_descriptor),
             icp_entry->log_root_descriptor_size);

  /* Copy the metadata if it exists. */
  if (icp_entry->log_root_descriptor.metadata_size > 0) {
    avb_memcpy(buffer + sizeof(TrillianLogRootDescriptor) - sizeof(uint8_t*),
               icp_entry->log_root_descriptor.metadata,
               icp_entry->log_root_descriptor.metadata_size);
  }
  /* Hash the result & clean up. */
  aftl_sha256(buffer, descriptor_size, hash);
  avb_free(buffer);
}

/* RFC 6962 Hashing function for leaves of a Merkle tree. */
void rfc6962_hash_leaf(uint8_t* leaf, uint64_t leaf_size, uint8_t* hash) {
  uint8_t* buffer;
  /* Computes a leaf hash as detailed by https://tools.ietf.org/html/rfc6962. */
  if (!leaf || !hash) return;

  buffer = (uint8_t*)avb_malloc(leaf_size + 1);

  if (!buffer) return;

  /* Prefix the data with a '0' for 2nd preimage attack resistance. */
  buffer[0] = 0;

  if (leaf_size > 0) avb_memcpy(buffer + 1, leaf, leaf_size);

  aftl_sha256(buffer, leaf_size + 1, hash);
  avb_free(buffer);
}

/* Computes an inner hash as detailed by https://tools.ietf.org/html/rfc6962. */
void rfc6962_hash_children(uint8_t* left_child,
                           uint64_t left_child_size,
                           uint8_t* right_child,
                           uint64_t right_child_size,
                           uint8_t* hash) {
  uint8_t* buffer;
  uint64_t data_size;
  /* Computes an inner hash detailed by https://tools.ietf.org/html/rfc6962. */
  if (!left_child || !right_child || !hash) return;

  /* Check for integer overflow. */
  if (left_child_size >= AFTL_ULONG_MAX - right_child_size) {
    return;
  }

  data_size = left_child_size + right_child_size + 1;

  buffer = (uint8_t*)avb_malloc(data_size);
  if (!buffer) return;

  /* Prefix the data with '1' for 2nd preimage attack resistance. */
  buffer[0] = 1;

  /* Copy the left child data, if it exists. */
  if (left_child_size > 0) avb_memcpy(buffer + 1, left_child, left_child_size);
  /* Copy the right child data, if it exists. */
  if (right_child_size > 0)
    avb_memcpy(buffer + 1 + left_child_size, right_child, right_child_size);

  /* Hash the concatenated data and clean up. */
  aftl_sha256(buffer, data_size, hash);
  avb_free(buffer);
}

/* Computes a subtree hash along the left-side tree border. */
void chain_border_right(uint8_t* seed,
                        uint64_t seed_size,
                        uint8_t proof[][AFTL_HASH_SIZE],
                        uint32_t proof_entry_count,
                        uint8_t* hash) {
  uint32_t i;
  uint8_t* tmp;
  uint8_t* tmp_hash;

  if (seed_size != AFTL_HASH_SIZE || !seed || !proof || !hash) {
    return;
  }

  tmp = seed;
  tmp_hash = (uint8_t*)avb_malloc(AFTL_HASH_SIZE);
  for (i = 0; i < proof_entry_count; i++) {
    rfc6962_hash_children(
        proof[i], AFTL_HASH_SIZE, tmp, AFTL_HASH_SIZE, tmp_hash);
    tmp = tmp_hash;
  }

  avb_memcpy(hash, tmp, AFTL_HASH_SIZE);
  avb_free(tmp_hash);
}

/* Computes a subtree hash on or below the tree's right border. */
void chain_inner(uint8_t* seed,
                 uint64_t seed_size,
                 uint8_t proof[][AFTL_HASH_SIZE],
                 uint32_t proof_entry_count,
                 uint64_t leaf_index,
                 uint8_t* hash) {
  uint32_t i;
  uint8_t* tmp = seed;
  uint8_t* tmp_hash;

  if (!seed || !proof || !hash) return;

  tmp = seed;
  tmp_hash = (uint8_t*)avb_malloc(AFTL_HASH_SIZE);

  for (i = 0; i < proof_entry_count; i++) {
    if ((leaf_index >> i & 1) == 0) {
      rfc6962_hash_children(tmp, seed_size, proof[i], AFTL_HASH_SIZE, tmp_hash);
    } else {
      rfc6962_hash_children(proof[i], AFTL_HASH_SIZE, tmp, seed_size, tmp_hash);
    }
    tmp = tmp_hash;
  }

  avb_memcpy(hash, tmp, AFTL_HASH_SIZE);
  avb_free(tmp_hash);
}

/* Counts leading zeros. Used in Merkle tree hash validation .*/
uint8_t aftl_clz(uint64_t val) {
  int r = 0;
  if (!val) return 64;
  if (!(val & 0xffffffff00000000u)) {
    val <<= 32;
    r += 32;
  }
  if (!(val & 0xffff000000000000u)) {
    val <<= 16;
    r += 16;
  }
  if (!(val & 0xff00000000000000u)) {
    val <<= 8;
    r += 8;
  }
  if (!(val & 0xf000000000000000u)) {
    val <<= 4;
    r += 4;
  }
  if (!(val & 0xc000000000000000u)) {
    val <<= 2;
    r += 2;
  }
  if (!(val & 0x8000000000000000u)) {
    val <<= 1;
    r += 1;
  }

  return r;
}

/* Calculates the expected Merkle tree hash. */
void root_from_icp(uint64_t leaf_index,
                   uint64_t tree_size,
                   uint8_t proof[][AFTL_HASH_SIZE],
                   uint32_t proof_entry_count,
                   uint8_t* leaf_hash,
                   uint64_t leaf_hash_size,
                   uint8_t* root_hash) {
  uint64_t inner_proof_size;
  uint64_t border_proof_size;
  uint64_t i;
  uint8_t hash[AFTL_HASH_SIZE];

  if (!proof || proof_entry_count == 0 || !leaf_hash || leaf_hash_size == 0 ||
      !root_hash)
    return;

  /* This cannot overflow. */
  inner_proof_size = 64 - aftl_clz(leaf_index ^ (tree_size - 1));

  /* Check for integer underflow.*/
  if ((proof_entry_count - inner_proof_size) > proof_entry_count) return;

  border_proof_size = proof_entry_count - inner_proof_size;
  /* Split the proof into two parts based on the calculated pivot point. */
  uint8_t inner_proof[inner_proof_size][AFTL_HASH_SIZE];
  uint8_t border_proof[border_proof_size][AFTL_HASH_SIZE];

  for (i = 0; i < inner_proof_size; i++) {
    avb_memcpy(inner_proof[i], proof[i], AFTL_HASH_SIZE);
  }
  for (i = 0; i < border_proof_size; i++) {
    avb_memcpy(border_proof[i], proof[inner_proof_size + i], AFTL_HASH_SIZE);
  }

  /* Calculate the root hash and store it in root_hash. */
  chain_inner(leaf_hash,
              leaf_hash_size,
              inner_proof,
              inner_proof_size,
              leaf_index,
              hash);

  chain_border_right(
      hash, AFTL_HASH_SIZE, border_proof, border_proof_size, root_hash);
}
