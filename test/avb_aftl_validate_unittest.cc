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

#include <gtest/gtest.h>

#include <libavb_aftl/libavb_aftl.h>

#include "avb_unittest_util.h"

namespace avb {

/* Extend BaseAvbToolTest to look for memory leaks. */
class AvbAftlValidateTest : public BaseAvbToolTest {
 public:
  AvbAftlValidateTest() {}
};

/*TODO:(danielaustin) Re-enable this once the sig validation is implemented. */
/*
TEST_F(AvbAftlValidateTest, AftlVerifySignature) {
  AftlIcpEntry icp_entry;
  uint8_t *key;
  size_t key_num_bytes;

  FILE * f = fopen("test/data/testkey_rsa4096.pem", "r");
  fseek(f, 0, SEEK_END);
  key_num_bytes = ftell(f);
  rewind(f);
  key = (uint8_t *)avb_malloc(key_num_bytes);
  fread(key, 1, key_num_bytes, f);
  fclose(f);

  icp_entry.log_root_sig_size = AFTL_SIGNATURE_SIZE;
  icp_entry.log_root_signature = (uint8_t *)avb_malloc(AFTL_SIGNATURE_SIZE);
  avb_memcpy(icp_entry.log_root_signature,
             "\x3F\x9B\x25\xE2\xD8\x8C\xCD\x62\x2D\xC1\xD6\x99\x28\x07\x59\x64"
             "\x16\x54\x4D\x5A\x67\x12\xAF\xA8\x0E\x78\x2B\xEA\x63\x9A\x5F\x90"
             "\xB9\x95\x4E\xB6\xE5\x12\x94\x6E\x97\x6C\xA1\xAE\xEF\xAF\xCD\x1E"
             "\xF8\xEC\x95\x57\x68\x3A\xD6\x2A\xEA\x9E\x67\xC5\xEF\x48\x5B\x5D"
             "\xDE\x14\xEE\xA7\x77\x6E\xF7\xA0\xC6\x19\x4A\xC5\x6A\xD8\xAB\xBC"
             "\x3F\xBF\xA6\xFA\x2D\xE2\x3C\x62\x6E\xE6\x6E\xCE\x50\xB1\xDD\x9B"
             "\x01\x39\x2A\xF8\x0A\x6B\x3C\xA5\x23\x8A\xA7\x47\x13\x44\xF3\x33"
             "\x2D\x6C\x12\xA9\x2B\xEC\x0E\x62\x5A\x28\xC1\xEA\xE9\xF1\x75\x8F"
             "\x4C\x89\x52\x12\x36\xDD\x9E\xA3\x4E\x4D\x14\x65\x27\x2A\xE1\x8E"
             "\x11\x80\x46\xC2\x85\x78\xC0\xE4\x66\x00\xCD\x25\x7C\x30\x5B\x35"
             "\x46\x62\xE2\xE1\x1E\x84\xFD\x75\xE4\xFF\x14\xEF\x6E\x20\xB5\x38"
             "\xCF\xCC\x1B\x38\xA3\xD2\x02\xDA\x4D\x6A\x03\x43\x70\x86\x7B\x52"
             "\xD5\xB7\x2E\x5F\x64\x97\x7F\x5A\xF8\xB6\xE7\x51\x0A\x17\x13\x38"
             "\x23\x87\x43\x69\x0B\x18\x7A\x67\x40\xFB\xC0\xFA\x0E\xEC\xF8\x3C"
             "\x4D\xB6\x17\x79\x68\xEA\x82\xBA\x3F\x09\x39\xDE\x2F\x84\x6F\x31"
             "\x3A\xBF\x0C\xE2\xDC\x16\xDB\xB3\x2F\x32\x91\x89\xE5\x2C\x6C\xBC"
             "\xE1\xB4\x69\xCB\x3B\x5C\x46\xC1\x8C\x59\xC0\x77\xF8\x23\xC4\xFB"
             "\x90\xE1\x03\x39\xD2\x08\xD9\x4F\x84\x56\xF0\xE9\x27\x68\x92\x41"
             "\x2A\x6F\x40\xD9\x2F\x85\x5C\x95\x57\xB3\x66\xBF\xEA\x09\x7F\x06"
             "\x28\x50\x1D\x52\x31\xE6\x30\x59\x17\x87\x8E\x33\xE5\x45\x6B\x1B"
             "\xE2\x0F\x28\x0A\xF1\x8A\x79\xDC\x6C\x09\x80\x6E\x4E\x97\xB9\xBC"
             "\x74\xCF\xFE\xEF\x84\xAE\xA4\xC4\xC1\x17\x16\x3D\x03\x50\xD3\x38"
             "\xD2\x97\xFD\x3B\x30\xA4\x9C\x70\xA1\x8E\x4A\xD6\x10\x50\x21\x36"
             "\x77\xB4\xF9\xC3\xFA\xFE\x9E\x2C\xE5\xF8\xC2\x77\xBC\x09\xF7\xC0"
             "\x34\xBB\x31\xBE\x7A\xF4\x3A\xF3\xB1\x28\x7A\x16\x95\x2E\x31\x9B"
             "\x92\xAE\xC3\x13\x6D\xC1\xE5\x57\x2E\xC0\x77\xC2\xE8\x1E\x8B\xF3"
             "\xDF\x5C\xEC\xC5\xFA\x3A\x24\x6E\xE5\xC0\x0B\x95\xA8\x9C\x86\x05"
             "\x8F\xA3\x08\x60\x24\xE1\x54\x71\x6A\x43\x43\x43\xEE\xE3\x4D\x15"
             "\xD8\xED\xBB\x7E\xEA\xF7\xC9\x81\x1D\xC2\x35\xCB\x03\x39\xB4\x5D"
             "\x37\x34\x08\xDF\x5B\xCA\x67\x68\xE7\x6A\x6E\x16\x8F\x75\x1B\x95"
             "\xC4\x5D\x67\xD5\xA0\xC6\x4C\x44\x31\xB5\x0A\xEF\x18\x56\x0F\x43"
             "\xC6\xF3\x9A\x39\x67\x16\xC2\x6D\x39\x0D\xA9\x96\xF0\xB6\x41\x03",
             512);
  icp_entry.log_root_descriptor.version = 1;
  icp_entry.log_root_descriptor.tree_size = 8;
  icp_entry.log_root_descriptor.root_hash_size = 32;
  icp_entry.log_root_descriptor.timestamp = 322325503;
  icp_entry.log_root_descriptor.metadata_size = 0;
  icp_entry.log_root_descriptor.metadata = NULL;

  for(uint64_t i = 0; i < AFTL_HASH_SIZE; i++) {
    icp_entry.log_root_descriptor.root_hash[i] = 0;
  }

  EXPECT_EQ(true, aftl_verify_entry_signature(key, key_num_bytes, &icp_entry));
  avb_free(key);
  avb_free(icp_entry.log_root_signature);
}
*/

TEST_F(AvbAftlValidateTest, HashLogRootDescriptor) {
  uint8_t hash[AFTL_HASH_SIZE];
  AftlIcpEntry icp_entry;

  /* Initialize the icp_entry components used with the test. */
  icp_entry.log_root_descriptor.version = 1;
  icp_entry.log_root_descriptor.tree_size = 8;
  icp_entry.log_root_descriptor.root_hash_size = 32;
  icp_entry.log_root_descriptor.timestamp = 322325503;
  icp_entry.log_root_descriptor.metadata_size = 0;
  icp_entry.log_root_descriptor.metadata = NULL;

  for (uint64_t i = 0; i < AFTL_HASH_SIZE; i++) {
    icp_entry.log_root_descriptor.root_hash[i] = 0;
  }

  hash_log_root_descriptor(&icp_entry, hash);
  EXPECT_EQ("d4a6e703f7ba00ef5a9e96571ceecc8d0edcd37afe9cc100f1de06ada24c7c96",
            mem_to_hexstring(hash, AFTL_HASH_SIZE));
}

TEST_F(AvbAftlValidateTest, AftlVerifyIcpRootHash) {
  AftlIcpEntry* icp_entry;
  icp_entry = (AftlIcpEntry*)avb_malloc(sizeof(AftlIcpEntry) + AFTL_HASH_SIZE);

  /* Initialize the icp_entry components used with the test. */
  icp_entry->fw_info_leaf_size = 1;
  icp_entry->fw_info_leaf = (uint8_t*)avb_malloc(icp_entry->fw_info_leaf_size);
  avb_memcpy(icp_entry->fw_info_leaf, "\x10", 1);
  icp_entry->leaf_index = 2;
  icp_entry->log_root_descriptor.tree_size = 3;
  avb_memcpy(icp_entry->proofs[0],
             "\xfa\xc5\x42\x03\xe7\xcc\x69\x6c\xf0\xdf\xcb\x42\xc9\x2a\x1d\x9d"
             "\xba\xf7\x0a\xd9\xe6\x21\xf4\xbd\x8d\x98\x66\x2f\x00\xe3\xc1\x25",
             AFTL_HASH_SIZE);
  icp_entry->proof_hash_count = 1;
  avb_memcpy(icp_entry->log_root_descriptor.root_hash,
             "\xae\xb6\xbc\xfe\x27\x4b\x70\xa1\x4f\xb0\x67\xa5\xe5\x57\x82\x64"
             "\xdb\x0f\xa9\xb5\x1a\xf5\xe0\xba\x15\x91\x58\xf3\x29\xe0\x6e\x77",
             AFTL_HASH_SIZE);

  EXPECT_EQ(true, aftl_verify_icp_root_hash(icp_entry));
  avb_free(icp_entry->fw_info_leaf);
  avb_free(icp_entry);
}

TEST_F(AvbAftlValidateTest, AftlVerifyVbmetaHash) {
  AftlIcpEntry* icp_entry;

  icp_entry = (AftlIcpEntry*)avb_malloc(sizeof(AftlIcpEntry));
  /* Initialize the AftlIcpEntry components required for this test. */
  icp_entry->fw_info_leaf_size = AFTL_HASH_SIZE;
  icp_entry->fw_info_leaf = (uint8_t*)avb_malloc(AFTL_HASH_SIZE);
  avb_memcpy(icp_entry->fw_info_leaf,
             "\x65\xec\x58\x83\x43\x62\x8e\x81\x4d\xc7\x75\xa8\xcb\x77\x1f\x46"
             "\x81\xcc\x79\x6f\xba\x32\xf0\x68\xc7\x17\xce\x2e\xe2\x14\x4d\x39",
             AFTL_HASH_SIZE);
  GenerateVBMetaImage("vbmeta.img",
                      "SHA256_RSA4096",
                      0,
                      base::FilePath("test/data/testkey_rsa4096.pem"));

  EXPECT_EQ(true,
            aftl_verify_vbmeta_hash(
                vbmeta_image_.data(), vbmeta_image_.size(), icp_entry));
  avb_free(icp_entry->fw_info_leaf);
  avb_free(icp_entry);
}

TEST_F(AvbAftlValidateTest, RootFromIcp) {
  /* Tests from trillian root_from_icp functionality:
     https://github.com/google/trillian/blob/master/merkle/log_verifier_test.go
  */
  uint64_t leaf_index;
  uint64_t tree_size;
  uint8_t proof[3][AFTL_HASH_SIZE];
  uint8_t leaf_hash[AFTL_HASH_SIZE];
  uint8_t hash[AFTL_HASH_SIZE];

  leaf_index = 0;
  tree_size = 8;
  rfc6962_hash_leaf((uint8_t*)"", 0, leaf_hash);
  avb_memcpy(proof[0],
             "\x96\xa2\x96\xd2\x24\xf2\x85\xc6\x7b\xee\x93\xc3\x0f\x8a\x30\x91"
             "\x57\xf0\xda\xa3\x5d\xc5\xb8\x7e\x41\x0b\x78\x63\x0a\x09\xcf\xc7",
             AFTL_HASH_SIZE);
  avb_memcpy(proof[1],
             "\x5f\x08\x3f\x0a\x1a\x33\xca\x07\x6a\x95\x27\x98\x32\x58\x0d\xb3"
             "\xe0\xef\x45\x84\xbd\xff\x1f\x54\xc8\xa3\x60\xf5\x0d\xe3\x03\x1e",
             AFTL_HASH_SIZE);
  avb_memcpy(proof[2],
             "\x6b\x47\xaa\xf2\x9e\xe3\xc2\xaf\x9a\xf8\x89\xbc\x1f\xb9\x25\x4d"
             "\xab\xd3\x11\x77\xf1\x62\x32\xdd\x6a\xab\x03\x5c\xa3\x9b\xf6\xe4",
             AFTL_HASH_SIZE);
  root_from_icp(
      leaf_index, tree_size, proof, 3, leaf_hash, AFTL_HASH_SIZE, hash);
  EXPECT_EQ("5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
            mem_to_hexstring(hash, AFTL_HASH_SIZE));

  leaf_index = 5;
  tree_size = 8;
  rfc6962_hash_leaf((uint8_t*)"@ABC", 4, leaf_hash);
  avb_memcpy(proof[0],
             "\xbc\x1a\x06\x43\xb1\x2e\x4d\x2d\x7c\x77\x91\x8f\x44\xe0\xf4\xf7"
             "\x9a\x83\x8b\x6c\xf9\xec\x5b\x5c\x28\x3e\x1f\x4d\x88\x59\x9e\x6b",
             AFTL_HASH_SIZE);
  avb_memcpy(proof[1],
             "\xca\x85\x4e\xa1\x28\xed\x05\x0b\x41\xb3\x5f\xfc\x1b\x87\xb8\xeb"
             "\x2b\xde\x46\x1e\x9e\x3b\x55\x96\xec\xe6\xb9\xd5\x97\x5a\x0a\xe0",
             AFTL_HASH_SIZE);
  avb_memcpy(proof[2],
             "\xd3\x7e\xe4\x18\x97\x6d\xd9\x57\x53\xc1\xc7\x38\x62\xb9\x39\x8f"
             "\xa2\xa2\xcf\x9b\x4f\xf0\xfd\xfe\x8b\x30\xcd\x95\x20\x96\x14\xb7",
             AFTL_HASH_SIZE);
  root_from_icp(
      leaf_index, tree_size, proof, 3, leaf_hash, AFTL_HASH_SIZE, hash);
  EXPECT_EQ("5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
            mem_to_hexstring(hash, AFTL_HASH_SIZE));

  leaf_index = 2;
  tree_size = 3;
  rfc6962_hash_leaf((uint8_t*)"\x10", 1, leaf_hash);
  avb_memcpy(proof[0],
             "\xfa\xc5\x42\x03\xe7\xcc\x69\x6c\xf0\xdf\xcb\x42\xc9\x2a\x1d\x9d"
             "\xba\xf7\x0a\xd9\xe6\x21\xf4\xbd\x8d\x98\x66\x2f\x00\xe3\xc1\x25",
             AFTL_HASH_SIZE);
  root_from_icp(
      leaf_index, tree_size, proof, 1, leaf_hash, AFTL_HASH_SIZE, hash);
  EXPECT_EQ("aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
            mem_to_hexstring(hash, AFTL_HASH_SIZE));

  leaf_index = 1;
  tree_size = 5;
  rfc6962_hash_leaf((uint8_t*)"\x00", 1, leaf_hash);
  avb_memcpy(proof[0],
             "\x6e\x34\x0b\x9c\xff\xb3\x7a\x98\x9c\xa5\x44\xe6\xbb\x78\x0a\x2c"
             "\x78\x90\x1d\x3f\xb3\x37\x38\x76\x85\x11\xa3\x06\x17\xaf\xa0\x1d",
             AFTL_HASH_SIZE);
  avb_memcpy(proof[1],
             "\x5f\x08\x3f\x0a\x1a\x33\xca\x07\x6a\x95\x27\x98\x32\x58\x0d\xb3"
             "\xe0\xef\x45\x84\xbd\xff\x1f\x54\xc8\xa3\x60\xf5\x0d\xe3\x03\x1e",
             AFTL_HASH_SIZE);
  avb_memcpy(proof[2],
             "\xbc\x1a\x06\x43\xb1\x2e\x4d\x2d\x7c\x77\x91\x8f\x44\xe0\xf4\xf7"
             "\x9a\x83\x8b\x6c\xf9\xec\x5b\x5c\x28\x3e\x1f\x4d\x88\x59\x9e\x6b",
             AFTL_HASH_SIZE);
  root_from_icp(
      leaf_index, tree_size, proof, 3, leaf_hash, AFTL_HASH_SIZE, hash);
  EXPECT_EQ("4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
            mem_to_hexstring(hash, AFTL_HASH_SIZE));
}

TEST_F(AvbAftlValidateTest, ChainInner) {
  uint8_t hash[AFTL_HASH_SIZE];
  uint8_t seed[AFTL_HASH_SIZE];
  uint8_t proof[4][AFTL_HASH_SIZE];
  uint64_t i;

  for (i = 0; i < AFTL_HASH_SIZE; i++) {
    hash[i] = 0;
  }

  chain_inner(NULL, 0, proof, 0, 0, hash);
  EXPECT_EQ("0000000000000000000000000000000000000000000000000000000000000000",
            mem_to_hexstring(hash, AFTL_HASH_SIZE));
  chain_inner(
      (uint8_t*)"abcdabcdabcdabcdabcdabcdabcdabcd", 32, NULL, 0, 0, hash);
  EXPECT_EQ("0000000000000000000000000000000000000000000000000000000000000000",
            mem_to_hexstring(hash, AFTL_HASH_SIZE));
  avb_memcpy(seed, "1234567890abcdefghijklmnopqrstuv", AFTL_HASH_SIZE);
  avb_memcpy(proof[0], "abcdefghijklmnopqrstuvwxyz123456", AFTL_HASH_SIZE);
  chain_inner(seed, AFTL_HASH_SIZE, proof, 1, 0, hash);
  EXPECT_EQ("9cb6af81b146b6a81d911d26f4c0d467265a3385d6caf926d5515e58efd161a3",
            mem_to_hexstring(hash, AFTL_HASH_SIZE));
  avb_memcpy(proof[1], "7890abcdefghijklmnopqrstuvwxyz12", AFTL_HASH_SIZE);
  chain_inner(seed, AFTL_HASH_SIZE, proof, 2, 0, hash);
  EXPECT_EQ("368d8213cd7d62335a84b3a3d75c8a0302c0d63c93cbbd22c5396dc4c75ba019",
            mem_to_hexstring(hash, AFTL_HASH_SIZE));
  chain_inner(seed, AFTL_HASH_SIZE, proof, 2, 1, hash);
  EXPECT_EQ("78418158eb5943c50ec581b41f105ba9aecc1b9e7aba3ea2e93021cbd5bd166e",
            mem_to_hexstring(hash, AFTL_HASH_SIZE));
  avb_memcpy(proof[2], "abcdefghijklmn0pqrstuvwxyz123456", AFTL_HASH_SIZE);
  avb_memcpy(proof[3], "7890abcdefgh1jklmnopqrstuvwxyz12", AFTL_HASH_SIZE);
  chain_inner(seed, AFTL_HASH_SIZE, proof, 4, 1, hash);
  EXPECT_EQ("83309c48fb92707f5788b6dd4c9a89042dff20856ad9529b7fb8e5cdf47c04f8",
            mem_to_hexstring(hash, AFTL_HASH_SIZE));
  chain_inner(seed, AFTL_HASH_SIZE, proof, 4, 3, hash);
  EXPECT_EQ("13e5f7e441dc4dbea659acbc989ac33222f4447546e3dac36b0e0c9977d52b97",
            mem_to_hexstring(hash, AFTL_HASH_SIZE));
}

TEST_F(AvbAftlValidateTest, ChainBorderRight) {
  uint8_t hash[AFTL_HASH_SIZE];
  uint8_t seed[AFTL_HASH_SIZE];
  uint8_t proof[2][AFTL_HASH_SIZE];
  uint64_t i;

  for (i = 0; i < AFTL_HASH_SIZE; i++) {
    hash[i] = 0;
  }
  chain_border_right(NULL, 0, proof, 0, hash);
  EXPECT_EQ("0000000000000000000000000000000000000000000000000000000000000000",
            mem_to_hexstring(hash, AFTL_HASH_SIZE));
  chain_border_right((uint8_t*)"abcd", 4, proof, 1, hash);
  EXPECT_EQ("0000000000000000000000000000000000000000000000000000000000000000",
            mem_to_hexstring(hash, AFTL_HASH_SIZE));
  chain_border_right(
      (uint8_t*)"abcdabcdabcdabcdabcdabcdabcdabcd", 32, NULL, 0, hash);
  EXPECT_EQ("0000000000000000000000000000000000000000000000000000000000000000",
            mem_to_hexstring(hash, AFTL_HASH_SIZE));

  avb_memcpy(seed, "1234567890abcdefghijklmnopqrstuv", AFTL_HASH_SIZE);
  avb_memcpy(proof[0], "abcdefghijklmnopqrstuvwxyz123456", AFTL_HASH_SIZE);
  chain_border_right(seed, AFTL_HASH_SIZE, proof, 1, hash);
  EXPECT_EQ("363aa8a62b784be38392ab69ade1aac2562f8989ce8986bec685d2957d657310",
            mem_to_hexstring(hash, AFTL_HASH_SIZE));
  avb_memcpy(proof[1], "7890abcdefghijklmnopqrstuvwxyz12", AFTL_HASH_SIZE);
  chain_border_right(seed, AFTL_HASH_SIZE, proof, 2, hash);
  EXPECT_EQ("618fc58c45faea808e0bbe0f82afbe7687f4db2608824120e8ade507cbce221f",
            mem_to_hexstring(hash, AFTL_HASH_SIZE));
}

TEST_F(AvbAftlValidateTest, RFC6962HashChildren) {
  uint8_t hash[AFTL_HASH_SIZE];

  rfc6962_hash_children((uint8_t*)"", 0, (uint8_t*)"", 0, hash);
  EXPECT_EQ("4bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459a",
            mem_to_hexstring(hash, AFTL_HASH_SIZE));

  rfc6962_hash_children((uint8_t*)"abcd", 4, (uint8_t*)"", 0, hash);
  EXPECT_EQ("b75eb7b06e69c1c49597fba37398e0f5ba319c7164ed67bb19b41e9d576313b9",
            mem_to_hexstring(hash, AFTL_HASH_SIZE));

  rfc6962_hash_children((uint8_t*)"", 0, (uint8_t*)"efgh", 4, hash);
  EXPECT_EQ("8d65f3e92e3853cee633345caca3e035f01c2e44815371985baed2c45c10ca40",
            mem_to_hexstring(hash, AFTL_HASH_SIZE));

  rfc6962_hash_children((uint8_t*)"abcd", 4, (uint8_t*)"efgh", 4, hash);
  EXPECT_EQ("41561b1297f692dad705e28ece8bf47060fba1abeeebda0aa67c43570a36bf79",
            mem_to_hexstring(hash, AFTL_HASH_SIZE));
}

TEST_F(AvbAftlValidateTest, RFC6962HashLeaf) {
  uint8_t hash[AFTL_HASH_SIZE];
  rfc6962_hash_leaf((uint8_t*)"", 0, hash);
  EXPECT_EQ("6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
            mem_to_hexstring(hash, AFTL_HASH_SIZE));
  rfc6962_hash_leaf((uint8_t*)"abcdefg", 7, hash);
  EXPECT_EQ("6b43f785b72386e132b275bc918c25dbc687ab8427836bef6ce4509b64f4f54d",
            mem_to_hexstring(hash, AFTL_HASH_SIZE));
}

TEST_F(AvbAftlValidateTest, AftlSha256) {
  /* Computed with:
   *
   * $ echo -n foobar |sha256sum
   * c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2
   */
  uint8_t hash[AFTL_HASH_SIZE];
  aftl_sha256((uint8_t*)"foobar", 6, hash);
  EXPECT_EQ("c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2",
            mem_to_hexstring(hash, AFTL_HASH_SIZE));
}

TEST_F(AvbAftlValidateTest, AftlClz) {
  /* Spot checks to ensure aftl_clz is correct. */
  EXPECT_EQ(52ull, aftl_clz(4095));
  EXPECT_EQ(12ull, aftl_clz(0xfffffffffffff));
  EXPECT_EQ(64ull, aftl_clz(0));
  EXPECT_EQ(0ull, aftl_clz(0xffffffffffffffff));
}

}  // namespace avb
