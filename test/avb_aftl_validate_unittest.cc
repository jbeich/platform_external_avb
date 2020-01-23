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
             "\x0F\x74\xC1\xB5\x24\x2E\xCB\x78\x33\x1E\xAC\x32\x62\x06\x35\xE2"
             "\x7D\xD9\xE8\xB1\xF6\xE4\x80\x83\x5E\x4C\x6A\x67\xA3\xCD\x51\x74"
             "\x62\x7E\x69\xD3\xB4\x24\xE0\x8E\xD5\x55\x04\x93\xDF\x3B\x8A\x0B"
             "\xAE\x7E\x72\xAF\x7D\x05\x25\x4D\x01\x67\x1A\x2B\xDD\xFB\x27\x26"
             "\xB3\x2A\x8A\xE9\x17\x76\x3F\x11\x8F\x84\x44\x81\x90\x52\xE6\x7B"
             "\x47\x4A\xF7\xA9\x01\x79\xD4\xA2\xF5\xA1\x5B\xF5\x51\x38\x7A\x52"
             "\xB2\x0A\x3D\xC4\x0B\x27\xED\xF9\x12\x1B\x4D\x2D\xB9\x2E\xEE\xC7"
             "\x74\x61\xF6\xF0\x86\x07\x14\x9D\x27\xD6\xA0\x57\x68\x82\x18\xEB"
             "\xE0\x3F\xCE\xC9\xE0\x9D\x7B\xDD\x4A\x7A\x74\x3D\x36\x79\x8E\x6F"
             "\xE5\x60\xD3\x84\x0C\xAD\xFB\xA3\xB0\x22\x49\x97\xA8\xCD\x96\x99"
             "\x6C\x6A\x03\xDA\x14\x2F\x40\x7C\xDE\x15\xD2\x32\xE4\xA8\xF6\xAB"
             "\xCE\xE1\xDE\xF1\x1C\x59\xF8\x55\xD3\x4B\x14\xB1\xD9\x55\x00\x9E"
             "\x9E\x0F\x67\x00\xDD\x16\x80\x79\xB7\x53\x56\x4A\xFB\xF5\x71\xE9"
             "\x4D\xA1\x9D\xD3\x34\x5F\x19\xE7\x04\xAC\x4D\x23\x95\x50\x4D\x0D"
             "\xA2\x72\x32\x8C\x22\x62\xEE\x9C\xAD\xE1\xD1\xD5\xB3\xFE\x34\x4C"
             "\xEC\xBF\xC5\x92\xE1\x64\x56\xB5\x21\x21\x68\x3D\x43\xC9\x5E\xFE"
             "\x3A\xE2\x84\xF8\x48\x95\x36\x1F\xFA\x84\x83\x64\x05\x1E\x7F\xF6"
             "\x60\x73\x06\xE8\x23\x6C\xEA\x31\x00\xED\x28\x0A\x52\x77\x56\xA8"
             "\x0F\xA0\x67\xF5\x42\x0E\x5C\x1B\xF8\x25\xFC\xC1\x45\x40\x2F\xB5"
             "\xB5\x6A\xF4\xC7\x02\xA5\xE4\xEC\x89\xEA\xE2\xAF\x86\xE1\xCE\xDC"
             "\xB3\xED\x44\x8D\xBF\x04\x69\xDD\x96\x2D\x35\xC2\x62\xF4\x06\x4B"
             "\x14\x0E\x48\x54\x39\xEB\xAA\xB6\x97\x0D\x65\x46\x65\xF9\xDD\xEC"
             "\x37\x62\xAD\x10\xB2\xAD\x7E\xD3\xC4\x70\x58\x0E\x75\x6A\x69\x1F"
             "\x9C\x89\xAA\xD3\x66\x61\xEE\xC3\x3F\x85\x1F\xC9\x82\x30\x44\x27"
             "\x2A\xCB\xE9\xED\xC6\xA2\x6B\x42\xF6\x75\x8E\x93\x25\x95\xD8\x2A"
             "\x09\x4F\xF7\xD9\x36\x28\x65\xB4\xCE\x06\x4B\x7B\x68\x0C\x99\xDD"
             "\xC9\xDE\xB2\xC9\x67\x7C\x22\xC6\x73\x48\xD4\xED\x34\xD6\xAA\x4C"
             "\x3C\xD5\xE3\x51\x87\x75\xAB\xF1\x7E\xB0\x6E\x3F\x44\x46\xF9\x1A"
             "\xE6\x92\x63\x56\xD9\x9E\x0E\x51\x03\x07\x20\x11\xDC\xDB\xEC\x31"
             "\x2B\xE2\xA2\x4A\xD7\xE1\x23\xAC\x18\xA2\xB6\x5A\x4E\xB9\xBD\x8D"
             "\x2C\x6C\xCC\x96\xEB\xA9\xA0\x01\xCD\x79\x58\xD2\x87\xA9\x2E\xDE"
             "\x8C\xD7\xF7\xBA\xF4\xFD\x6A\xF1\x4A\x60\x4C\xF7\xA7\x2C\xA3\x08",
             512);
  icp_entry.log_root_descriptor.version = 1;
  icp_entry.log_root_descriptor.tree_size = 8;
  icp_entry.log_root_descriptor.root_hash_size = 32;
  icp_entry.log_root_descriptor.timestamp = 322325503;
  icp_entry.log_root_descriptor.revision = 0;
  icp_entry.log_root_descriptor.metadata_size = 0;
  icp_entry.log_root_descriptor.metadata = NULL;
  icp_entry.log_root_descriptor_size =
      icp_entry.log_root_descriptor.root_hash_size +
      icp_entry.log_root_descriptor.metadata_size + 29;
  icp_entry.log_root_descriptor.root_hash =
      (uint8_t*)avb_malloc(icp_entry.log_root_descriptor.root_hash_size);
  for (uint64_t i = 0; i < icp_entry.log_root_descriptor.root_hash_size; i++) {
    icp_entry.log_root_descriptor.root_hash[i] = 0;
  }

  EXPECT_EQ(true, aftl_verify_entry_signature(key, key_num_bytes, &icp_entry));
  avb_free(icp_entry.log_root_descriptor.root_hash);
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
  icp_entry.log_root_descriptor.revision = 0;
  icp_entry.log_root_descriptor.metadata_size = 0;
  icp_entry.log_root_descriptor.metadata = NULL;
  icp_entry.log_root_descriptor_size =
      icp_entry.log_root_descriptor.root_hash_size +
      icp_entry.log_root_descriptor.metadata_size + 29;

  icp_entry.log_root_descriptor.root_hash = (uint8_t*)avb_malloc(32);
  for (uint64_t i = 0; i < AFTL_HASH_SIZE; i++) {
    icp_entry.log_root_descriptor.root_hash[i] = 0;
  }

  hash_log_root_descriptor(&icp_entry, hash);
  EXPECT_EQ("55eb75ee6a6122d2cca0445b3d807ddaf74b257c0d3c0fd5fb6deecffae103b8",
            mem_to_hexstring(hash, AFTL_HASH_SIZE));
  avb_free(icp_entry.log_root_descriptor.root_hash);
}

TEST_F(AvbAftlValidateTest, AftlVerifyIcpRootHash) {
  AftlIcpEntry* icp_entry;
  uint32_t i;

  icp_entry = (AftlIcpEntry*)avb_malloc(sizeof(AftlIcpEntry) + AFTL_HASH_SIZE);

  /* Initialize the icp_entry components used with the test. */
  icp_entry->fw_info_leaf_size = AFTL_HASH_SIZE * 2 + 5;
  icp_entry->fw_info_leaf.vbmeta_hash_size = AFTL_HASH_SIZE;
  icp_entry->fw_info_leaf.vbmeta_hash = (uint8_t*)avb_malloc(AFTL_HASH_SIZE);
  for (i = 0; i < AFTL_HASH_SIZE; i++) {
    icp_entry->fw_info_leaf.vbmeta_hash[i] = 0;
  }
  icp_entry->fw_info_leaf.image_hash_size = AFTL_HASH_SIZE;
  icp_entry->fw_info_leaf.image_hash = (uint8_t*)avb_malloc(AFTL_HASH_SIZE);
  for (i = 0; i < AFTL_HASH_SIZE; i++) {
    icp_entry->fw_info_leaf.image_hash[i] = 0;
  }
  icp_entry->fw_info_leaf.build_fingerprint_size = 4;
  icp_entry->fw_info_leaf.build_fingerprint =
      (uint8_t*)avb_malloc(AFTL_HASH_SIZE);
  avb_memcpy(icp_entry->fw_info_leaf.build_fingerprint, "test", 4);
  icp_entry->leaf_index = 2;
  icp_entry->log_root_descriptor.tree_size = 3;
  avb_memcpy(icp_entry->proofs[0],
             "\xfa\xc5\x42\x03\xe7\xcc\x69\x6c\xf0\xdf\xcb\x42\xc9\x2a\x1d\x9d"
             "\xba\xf7\x0a\xd9\xe6\x21\xf4\xbd\x8d\x98\x66\x2f\x00\xe3\xc1\x25",
             AFTL_HASH_SIZE);
  icp_entry->proof_hash_count = 1;
  icp_entry->log_root_descriptor.root_hash =
      (uint8_t*)avb_malloc(AFTL_HASH_SIZE);
  avb_memcpy(icp_entry->log_root_descriptor.root_hash,
             "\xb2\x43\xb3\x5b\x52\xa1\xf6\x8e\xba\x09\x28\x59\x51\x7a\x1c\x22"
             "\xf9\x22\x72\x75\xeb\x42\x48\xa0\xc0\x85\x20\x41\xdc\x34\x18\x15",
             AFTL_HASH_SIZE);

  EXPECT_EQ(true, aftl_verify_icp_root_hash(icp_entry));
  avb_free(icp_entry->log_root_descriptor.root_hash);
  avb_free(icp_entry->fw_info_leaf.vbmeta_hash);
  avb_free(icp_entry->fw_info_leaf.image_hash);
  avb_free(icp_entry->fw_info_leaf.build_fingerprint);
  avb_free(icp_entry);
}

TEST_F(AvbAftlValidateTest, AftlVerifyVbmetaHash) {
  AftlIcpEntry* icp_entry;

  icp_entry = (AftlIcpEntry*)avb_malloc(sizeof(AftlIcpEntry));
  /* Initialize the AftlIcpEntry components required for this test. */
  icp_entry->fw_info_leaf.vbmeta_hash = (uint8_t*)avb_malloc(AFTL_HASH_SIZE);
  icp_entry->fw_info_leaf.vbmeta_hash_size = AFTL_HASH_SIZE;
  avb_memcpy(icp_entry->fw_info_leaf.vbmeta_hash,
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
  avb_free(icp_entry->fw_info_leaf.vbmeta_hash);
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
