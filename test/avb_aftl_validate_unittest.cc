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

TEST_F(AvbAftlValidateTest, AftlVerifySignature) {
  AftlIcpEntry icp_entry;
  uint8_t* key;
  size_t key_num_bytes;

  key_num_bytes = 1032;
  key = (uint8_t*)avb_malloc(key_num_bytes);
  avb_memcpy(key,
             "\x00\x00\x10\x00\x55\xd9\x04\xad\xd8\x04\xaf\xe3\xd3\x84\x6c\x7e"
             "\x0d\x89\x3d\xc2\x8c\xd3\x12\x55\xe9\x62\xc9\xf1\x0f\x5e\xcc\x16"
             "\x72\xab\x44\x7c\x2c\x65\x4a\x94\xb5\x16\x2b\x00\xbb\x06\xef\x13"
             "\x07\x53\x4c\xf9\x64\xb9\x28\x7a\x1b\x84\x98\x88\xd8\x67\xa4\x23"
             "\xf9\xa7\x4b\xdc\x4a\x0f\xf7\x3a\x18\xae\x54\xa8\x15\xfe\xb0\xad"
             "\xac\x35\xda\x3b\xad\x27\xbc\xaf\xe8\xd3\x2f\x37\x34\xd6\x51\x2b"
             "\x6c\x5a\x27\xd7\x96\x06\xaf\x6b\xb8\x80\xca\xfa\x30\xb4\xb1\x85"
             "\xb3\x4d\xaa\xaa\xc3\x16\x34\x1a\xb8\xe7\xc7\xfa\xf9\x09\x77\xab"
             "\x97\x93\xeb\x44\xae\xcf\x20\xbc\xf0\x80\x11\xdb\x23\x0c\x47\x71"
             "\xb9\x6d\xd6\x7b\x60\x47\x87\x16\x56\x93\xb7\xc2\x2a\x9a\xb0\x4c"
             "\x01\x0c\x30\xd8\x93\x87\xf0\xed\x6e\x8b\xbe\x30\x5b\xf6\xa6\xaf"
             "\xdd\x80\x7c\x45\x5e\x8f\x91\x93\x5e\x44\xfe\xb8\x82\x07\xee\x79"
             "\xca\xbf\x31\x73\x62\x58\xe3\xcd\xc4\xbc\xc2\x11\x1d\xa1\x4a\xbf"
             "\xfe\x27\x7d\xa1\xf6\x35\xa3\x5e\xca\xdc\x57\x2f\x3e\xf0\xc9\x5d"
             "\x86\x6a\xf8\xaf\x66\xa7\xed\xcd\xb8\xed\xa1\x5f\xba\x9b\x85\x1a"
             "\xd5\x09\xae\x94\x4e\x3b\xcf\xcb\x5c\xc9\x79\x80\xf7\xcc\xa6\x4a"
             "\xa8\x6a\xd8\xd3\x31\x11\xf9\xf6\x02\x63\x2a\x1a\x2d\xd1\x1a\x66"
             "\x1b\x16\x41\xbd\xbd\xf7\x4d\xc0\x4a\xe5\x27\x49\x5f\x7f\x58\xe3"
             "\x27\x2d\xe5\xc9\x66\x0e\x52\x38\x16\x38\xfb\x16\xeb\x53\x3f\xe6"
             "\xfd\xe9\xa2\x5e\x25\x59\xd8\x79\x45\xff\x03\x4c\x26\xa2\x00\x5a"
             "\x8e\xc2\x51\xa1\x15\xf9\x7b\xf4\x5c\x81\x9b\x18\x47\x35\xd8\x2d"
             "\x05\xe9\xad\x0f\x35\x74\x15\xa3\x8e\x8b\xcc\x27\xda\x7c\x5d\xe4"
             "\xfa\x04\xd3\x05\x0b\xba\x3a\xb2\x49\x45\x2f\x47\xc7\x0d\x41\x3f"
             "\x97\x80\x4d\x3f\xc1\xb5\xbb\x70\x5f\xa7\x37\xaf\x48\x22\x12\x45"
             "\x2e\xf5\x0f\x87\x92\xe2\x84\x01\xf9\x12\x0f\x14\x15\x24\xce\x89"
             "\x99\xee\xb9\xc4\x17\x70\x70\x15\xea\xbe\xc6\x6c\x1f\x62\xb3\xf4"
             "\x2d\x16\x87\xfb\x56\x1e\x45\xab\xae\x32\xe4\x5e\x91\xed\x53\x66"
             "\x5e\xbd\xed\xad\xe6\x12\x39\x0d\x83\xc9\xe8\x6b\x6c\x2d\xa5\xee"
             "\xc4\x5a\x66\xae\x8c\x97\xd7\x0d\x6c\x49\xc7\xf5\xc4\x92\x31\x8b"
             "\x09\xee\x33\xda\xa9\x37\xb6\x49\x18\xf8\x0e\x60\x45\xc8\x33\x91"
             "\xef\x20\x57\x10\xbe\x78\x2d\x83\x26\xd6\xca\x61\xf9\x2f\xe0\xbf"
             "\x05\x30\x52\x5a\x12\x1c\x00\xa7\x5d\xcc\x7c\x2e\xc5\x95\x8b\xa3"
             "\x3b\xf0\x43\x2e\x5e\xdd\x00\xdb\x0d\xb3\x37\x99\xa9\xcd\x9c\xb7"
             "\x43\xf7\x35\x44\x21\xc2\x82\x71\xab\x8d\xaa\xb4\x41\x11\xec\x1e"
             "\x8d\xfc\x14\x82\x92\x4e\x83\x6a\x0a\x6b\x35\x5e\x5d\xe9\x5c\xcc"
             "\x8c\xde\x39\xd1\x4a\x5b\x5f\x63\xa9\x64\xe0\x0a\xcb\x0b\xb8\x5a"
             "\x7c\xc3\x0b\xe6\xbe\xfe\x8b\x0f\x7d\x34\x8e\x02\x66\x74\x01\x6c"
             "\xca\x76\xac\x7c\x67\x08\x2f\x3f\x1a\xa6\x2c\x60\xb3\xff\xda\x8d"
             "\xb8\x12\x0c\x00\x7f\xcc\x50\xa1\x5c\x64\xa1\xe2\x5f\x32\x65\xc9"
             "\x9c\xbe\xd6\x0a\x13\x87\x3c\x2a\x45\x47\x0c\xca\x42\x82\xfa\x89"
             "\x65\xe7\x89\xb4\x8f\xf7\x1e\xe6\x23\xa5\xd0\x59\x37\x79\x92\xd7"
             "\xce\x3d\xfd\xe3\xa1\x0b\xcf\x6c\x85\xa0\x65\xf3\x5c\xc6\x4a\x63"
             "\x5f\x6e\x3a\x3a\x2a\x8b\x6a\xb6\x2f\xbb\xf8\xb2\x4b\x62\xbc\x1a"
             "\x91\x25\x66\xe3\x69\xca\x60\x49\x0b\xf6\x8a\xbe\x3e\x76\x53\xc2"
             "\x7a\xa8\x04\x17\x75\xf1\xf3\x03\x62\x1b\x85\xb2\xb0\xef\x80\x15"
             "\xb6\xd4\x4e\xdf\x71\xac\xdb\x2a\x04\xd4\xb4\x21\xba\x65\x56\x57"
             "\xe8\xfa\x84\xa2\x7d\x13\x0e\xaf\xd7\x9a\x58\x2a\xa3\x81\x84\x8d"
             "\x09\xa0\x6a\xc1\xbb\xd9\xf5\x86\xac\xbd\x75\x61\x09\xe6\x8c\x3d"
             "\x77\xb2\xed\x30\x20\xe4\x00\x1d\x97\xe8\xbf\xc7\x00\x1b\x21\xb1"
             "\x16\xe7\x41\x67\x2e\xec\x38\xbc\xe5\x1b\xb4\x06\x23\x31\x71\x1c"
             "\x49\xcd\x76\x4a\x76\x36\x8d\xa3\x89\x8b\x4a\x7a\xf4\x87\xc8\x15"
             "\x0f\x37\x39\xf6\x6d\x80\x19\xef\x5c\xa8\x66\xce\x1b\x16\x79\x21"
             "\xdf\xd7\x31\x30\xc4\x21\xdd\x34\x5b\xd2\x1a\x2b\x3e\x5d\xf7\xea"
             "\xca\x05\x8e\xb7\xcb\x49\x2e\xa0\xe3\xf4\xa7\x48\x19\x10\x9c\x04"
             "\xa7\xf4\x28\x74\xc8\x6f\x63\x20\x2b\x46\x24\x26\x19\x1d\xd1\x2c"
             "\x31\x6d\x5a\x29\xa2\x06\xa6\xb2\x41\xcc\x0a\x27\x96\x09\x96\xac"
             "\x47\x65\x78\x68\x51\x98\xd6\xd8\xa6\x2d\xa0\xcf\xec\xe2\x74\xf2"
             "\x82\xe3\x97\xd9\x7e\xd4\xf8\x0b\x70\x43\x3d\xb1\x7b\x97\x80\xd6"
             "\xcb\xd7\x19\xbc\x63\x0b\xfd\x4d\x88\xfe\x67\xac\xb8\xcc\x50\xb7"
             "\x68\xb3\x5b\xd6\x1e\x25\xfc\x5f\x3c\x8d\xb1\x33\x7c\xb3\x49\x01"
             "\x3f\x71\x55\x0e\x51\xba\x61\x26\xfa\xea\xe5\xb5\xe8\xaa\xcf\xcd"
             "\x96\x9f\xd6\xc1\x5f\x53\x91\xad\x05\xde\x20\xe7\x51\xda\x5b\x95"
             "\x67\xed\xf4\xee\x42\x65\x70\x13\x0b\x70\x14\x1c\xc9\xe0\x19\xca"
             "\x5f\xf5\x1d\x70\x4b\x6c\x06\x74\xec\xb5\x2e\x77\xe1\x74\xa1\xa3"
             "\x99\xa0\x85\x9e\xf1\xac\xd8\x7e",
             key_num_bytes);

  icp_entry.log_root_sig_size = AFTL_SIGNATURE_SIZE;
  icp_entry.log_root_signature = (uint8_t*)avb_malloc(AFTL_SIGNATURE_SIZE);
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

  for (uint64_t i = 0; i < AFTL_HASH_SIZE; i++) {
    icp_entry.log_root_descriptor.root_hash[i] = 0;
  }

  EXPECT_EQ(true, aftl_verify_entry_signature(key, key_num_bytes, &icp_entry));
  avb_free(key);
  avb_free(icp_entry.log_root_signature);
}

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
