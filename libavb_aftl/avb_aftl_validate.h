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

#if !defined(AVB_INSIDE_LIBAVB_AFTL_H) && !defined(AVB_COMPILATION)
#error "Never include this file directly, include libavb_aftl/libavb_aftl.h."
#endif

#ifndef AVB_AFTL_VALIDATE_H_
#define AVB_AFTL_VALIDATE_H_

#include <libavb/libavb.h>
#include "avb_aftl_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define AFTL_ULONG_MAX 0xfffffffffffffffful

/* Verifies that the logged vbmeta hash matches the one on device. */
bool aftl_verify_vbmeta_hash(
    uint8_t* vbmeta,          /* Buffer containing the vbmeta data. */
    size_t vbmeta_size,       /* Size of the vbmeta buffer. */
    AftlIcpEntry* icp_entry); /* Pointer to the AftlIcpEntry to verify. */

/* Verifies the Merkle tree root hash. */
bool aftl_verify_icp_root_hash(
    AftlIcpEntry* icp_entry); /* Pointer to the AftlIcpEntry to verify. */

/* Verifies the log root signature for the transparency log submission. */
bool aftl_verify_entry_signature(
    const uint8_t* key,       /* Transparency log public key data. */
    size_t key_num_bytes,     /* Size of the key data. */
    AftlIcpEntry* icp_entry); /* Pointer to the AftlIcpEntry to verify. */

/* Performs a SHA256 hash operation on data. */
void aftl_sha256(uint8_t* data,                 /* Data to be hashed. */
                 uint64_t length,               /* Size of data to be hashed. */
                 uint8_t hash[AFTL_HASH_SIZE]); /* The resulting SHA256 hash. */

/* Calculates a SHA256 hash of the TrillianLogRootDescriptor in icp_entry. */
void hash_log_root_descriptor(
    AftlIcpEntry* icp_entry, /* The icp_entry containing the descriptor. */
    uint8_t* hash);          /* The resulting hash of the descriptor data. */

/* RFC 6962 Hashing function for leaves of a Merkle tree. */
void rfc6962_hash_leaf(
    uint8_t* leaf,      /* The Merkle tree leaf data to be hashed. */
    uint64_t leaf_size, /* Size of the leaf data. */
    uint8_t* hash);     /* Resulting RFC 6962 hash of the leaf data. */

/* Computes an inner hash as detailed by https://tools.ietf.org/html/rfc6962. */
void rfc6962_hash_children(
    uint8_t* left_child,           /* The left child node data. */
    uint64_t left_child_size,      /* Size of the left child node data. */
    uint8_t* right_child,          /* The right child node data. */
    uint64_t right_child_size,     /* Size of the right child node data. */
    uint8_t hash[AFTL_HASH_SIZE]); /* Resulting RFC 6962 hash of the children.*/

/* Computes a subtree hash along the left-side tree border. */
void chain_border_right(
    uint8_t* seed,                   /* Data containing the starting hash. */
    uint64_t seed_size,              /* Size of the starting hash data. */
    uint8_t proof[][AFTL_HASH_SIZE], /* The hashes in the inclusion proof. */
    uint32_t proof_entry_count,      /* Number of inclusion proof entries. */
    uint8_t* hash);                  /* Resulting subtree hash. */

/* Computes a subtree hash on or below the tree's right border. */
void chain_inner(
    uint8_t* seed,                   /* Data containing the starting hash. */
    uint64_t seed_size,              /* Size of the starting hash data. */
    uint8_t proof[][AFTL_HASH_SIZE], /* The hashes in the inclusion proof. */
    uint32_t proof_entry_count,      /* Number of inclusion proof entries. */
    uint64_t leaf_index,             /* The current Merkle tree leaf index. */
    uint8_t* hash);                  /* Resulting subtree hash. */

/* Counts leading zeros. Used in Merkle tree hash validation .*/
uint8_t aftl_count_leading_zeros(
    uint64_t val); /* Value to count leading zeros of. */

/* Calculates the expected Merkle tree hash. */
void root_from_icp(
    uint64_t leaf_index,             /* The leaf index in the Merkle tree.*/
    uint64_t tree_size,              /* The size of the Merkle tree. */
    uint8_t proof[][AFTL_HASH_SIZE], /* Inclusion proof hash data. */
    uint32_t proof_entry_count,      /* Number of inclusion proof hashes. */
    uint8_t* leaf_hash,              /* The leaf hash to prove inclusion of. */
    uint64_t leaf_hash_size,         /* Size of the leaf hash. */
    uint8_t* root_hash);             /* The resulting tree root hash. */

#ifdef __cplusplus
}
#endif

#endif /* AVB_AFTL_VALIDATE_H_ */
