/*
 * Copyright (C) 2016 The Android Open Source Project
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

#include <iostream>

#include <endian.h>
#include <inttypes.h>
#include <string.h>

#include <base/files/file_util.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>

#include <libavb/avb_sha.h>
#include <libavb/libavb.h>

#include "avb_unittest_util.h"

namespace avb {

class AvbToolTest : public BaseAvbToolTest {
 public:
  AvbToolTest() {}

  void AddHashFooterTest(bool sparse_image);
  void AddHashtreeFooterTest(bool sparse_image);
  void AddHashtreeFooterFECTest(bool sparse_image);
};

// This test ensure that the version is increased in both
// avb_boot_image.h and the avb tool.
TEST_F(AvbToolTest, AvbVersionInSync) {
  base::FilePath path = testdir_.Append("version.txt");
  EXPECT_COMMAND(0, "./avbtool version > %s", path.value().c_str());
  std::string printed_version;
  ASSERT_TRUE(base::ReadFileToString(path, &printed_version));
  base::TrimWhitespaceASCII(printed_version, base::TRIM_ALL, &printed_version);
  std::string expected_version =
      base::StringPrintf("%d.%d", AVB_MAJOR_VERSION, AVB_MINOR_VERSION);
  EXPECT_EQ(printed_version, expected_version);
}

TEST_F(AvbToolTest, ExtractPublicKey) {
  GenerateVBMetaImage("vbmeta.img",
                      "SHA256_RSA2048",
                      0,
                      base::FilePath("test/data/testkey_rsa2048.pem"));

  std::string key_data =
      PublicKeyAVB(base::FilePath("test/data/testkey_rsa2048.pem"));

  AvbVBMetaImageHeader h;
  avb_vbmeta_image_header_to_host_byte_order(
      reinterpret_cast<AvbVBMetaImageHeader*>(vbmeta_image_.data()), &h);
  uint8_t* d = reinterpret_cast<uint8_t*>(vbmeta_image_.data());
  size_t auxiliary_data_block_offset =
      sizeof(AvbVBMetaImageHeader) + h.authentication_data_block_size;
  EXPECT_GT(h.auxiliary_data_block_size, key_data.size());
  EXPECT_EQ(0,
            memcmp(key_data.data(),
                   d + auxiliary_data_block_offset + h.public_key_offset,
                   key_data.size()));
}

TEST_F(AvbToolTest, CheckDescriptors) {
  GenerateVBMetaImage("vbmeta.img",
                      "SHA256_RSA2048",
                      0,
                      base::FilePath("test/data/testkey_rsa2048.pem"),
                      "--prop foo:brillo "
                      "--prop bar:chromeos "
                      "--prop prisoner:24601 "
                      "--prop hexnumber:0xcafe "
                      "--prop hexnumber_capital:0xCAFE "
                      "--prop large_hexnumber:0xfedcba9876543210 "
                      "--prop larger_than_uint64:0xfedcba98765432101 "
                      "--prop almost_a_number:423x "
                      "--prop_from_file blob:test/data/small_blob.bin ");

  AvbVBMetaImageHeader h;
  avb_vbmeta_image_header_to_host_byte_order(
      reinterpret_cast<AvbVBMetaImageHeader*>(vbmeta_image_.data()), &h);

  EXPECT_EQ(AVB_VBMETA_VERIFY_RESULT_OK,
            avb_vbmeta_image_verify(
                vbmeta_image_.data(), vbmeta_image_.size(), nullptr, nullptr));

  const char* s;
  size_t len;
  uint64_t val;

  // Basic.
  s = avb_property_lookup(
      vbmeta_image_.data(), vbmeta_image_.size(), "foo", 0, &len);
  EXPECT_EQ(0, strcmp(s, "brillo"));
  EXPECT_EQ(6U, len);
  s = avb_property_lookup(
      vbmeta_image_.data(), vbmeta_image_.size(), "bar", 0, &len);
  EXPECT_EQ(0, strcmp(s, "chromeos"));
  EXPECT_EQ(8U, len);
  s = avb_property_lookup(
      vbmeta_image_.data(), vbmeta_image_.size(), "non-existant", 0, &len);
  EXPECT_EQ(0U, len);
  EXPECT_EQ(NULL, s);

  // Numbers.
  EXPECT_NE(
      0,
      avb_property_lookup_uint64(
          vbmeta_image_.data(), vbmeta_image_.size(), "prisoner", 0, &val));
  EXPECT_EQ(24601U, val);

  EXPECT_NE(
      0,
      avb_property_lookup_uint64(
          vbmeta_image_.data(), vbmeta_image_.size(), "hexnumber", 0, &val));
  EXPECT_EQ(0xcafeU, val);

  EXPECT_NE(0,
            avb_property_lookup_uint64(vbmeta_image_.data(),
                                       vbmeta_image_.size(),
                                       "hexnumber_capital",
                                       0,
                                       &val));
  EXPECT_EQ(0xcafeU, val);

  EXPECT_NE(0,
            avb_property_lookup_uint64(vbmeta_image_.data(),
                                       vbmeta_image_.size(),
                                       "large_hexnumber",
                                       0,
                                       &val));
  EXPECT_EQ(0xfedcba9876543210U, val);

  // We could catch overflows and return an error ... but we currently don't.
  EXPECT_NE(0,
            avb_property_lookup_uint64(vbmeta_image_.data(),
                                       vbmeta_image_.size(),
                                       "larger_than_uint64",
                                       0,
                                       &val));
  EXPECT_EQ(0xedcba98765432101U, val);

  // Number-parsing failures.
  EXPECT_EQ(0,
            avb_property_lookup_uint64(
                vbmeta_image_.data(), vbmeta_image_.size(), "foo", 0, &val));

  EXPECT_EQ(0,
            avb_property_lookup_uint64(vbmeta_image_.data(),
                                       vbmeta_image_.size(),
                                       "almost_a_number",
                                       0,
                                       &val));

  // Blobs.
  //
  // test/data/small_blob.bin is 21 byte file full of NUL-bytes except
  // for the string "brillo ftw!" at index 2 and '\n' at the last
  // byte.
  s = avb_property_lookup(
      vbmeta_image_.data(), vbmeta_image_.size(), "blob", 0, &len);
  EXPECT_EQ(21U, len);
  EXPECT_EQ(0, memcmp(s, "\0\0", 2));
  EXPECT_EQ(0, memcmp(s + 2, "brillo ftw!", 11));
  EXPECT_EQ(0, memcmp(s + 13, "\0\0\0\0\0\0\0", 7));
  EXPECT_EQ('\n', s[20]);
}

TEST_F(AvbToolTest, CheckRollbackIndex) {
  uint64_t rollback_index = 42;
  GenerateVBMetaImage("vbmeta.img",
                      "SHA256_RSA2048",
                      rollback_index,
                      base::FilePath("test/data/testkey_rsa2048.pem"));

  AvbVBMetaImageHeader h;
  avb_vbmeta_image_header_to_host_byte_order(
      reinterpret_cast<AvbVBMetaImageHeader*>(vbmeta_image_.data()), &h);

  EXPECT_EQ(rollback_index, h.rollback_index);
}

TEST_F(AvbToolTest, CheckPubkeyReturned) {
  GenerateVBMetaImage("vbmeta.img",
                      "SHA256_RSA2048",
                      0,
                      base::FilePath("test/data/testkey_rsa2048.pem"));

  const uint8_t* pubkey = NULL;
  size_t pubkey_length = 0;

  EXPECT_EQ(
      AVB_VBMETA_VERIFY_RESULT_OK,
      avb_vbmeta_image_verify(
          vbmeta_image_.data(), vbmeta_image_.size(), &pubkey, &pubkey_length));

  AvbVBMetaImageHeader h;
  avb_vbmeta_image_header_to_host_byte_order(
      reinterpret_cast<AvbVBMetaImageHeader*>(vbmeta_image_.data()), &h);

  EXPECT_EQ(pubkey_length, h.public_key_size);

  const uint8_t* expected_pubkey =
      vbmeta_image_.data() + sizeof(AvbVBMetaImageHeader) +
      h.authentication_data_block_size + h.public_key_offset;
  EXPECT_EQ(pubkey, expected_pubkey);
}

TEST_F(AvbToolTest, Info) {
  GenerateVBMetaImage("vbmeta.img",
                      "SHA256_RSA2048",
                      0,
                      base::FilePath("test/data/testkey_rsa2048.pem"),
                      "--prop foo:brillo "
                      "--prop bar:chromeos "
                      "--prop prisoner:24601 "
                      "--prop hexnumber:0xcafe "
                      "--prop hexnumber_capital:0xCAFE "
                      "--prop large_hexnumber:0xfedcba9876543210 "
                      "--prop larger_than_uint64:0xfedcba98765432101 "
                      "--prop almost_a_number:423x "
                      "--prop_from_file blob:test/data/small_blob.bin "
                      "--prop_from_file large_blob:test/data/large_blob.bin");

  ASSERT_EQ(
      "VBMeta image version:     1.0\n"
      "Header Block:             256 bytes\n"
      "Authentication Block:     576 bytes\n"
      "Auxiliary Block:          3200 bytes\n"
      "Algorithm:                SHA256_RSA2048\n"
      "Rollback Index:           0\n"
      "Flags:                    0\n"
      "Descriptors:\n"
      "    Prop: foo -> 'brillo'\n"
      "    Prop: bar -> 'chromeos'\n"
      "    Prop: prisoner -> '24601'\n"
      "    Prop: hexnumber -> '0xcafe'\n"
      "    Prop: hexnumber_capital -> '0xCAFE'\n"
      "    Prop: large_hexnumber -> '0xfedcba9876543210'\n"
      "    Prop: larger_than_uint64 -> '0xfedcba98765432101'\n"
      "    Prop: almost_a_number -> '423x'\n"
      "    Prop: blob -> '\\x00\\x00brillo "
      "ftw!\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\n'\n"
      "    Prop: large_blob -> (2048 bytes)\n",
      InfoImage(vbmeta_image_path_));
}

static bool collect_descriptors(const AvbDescriptor* descriptor,
                                void* user_data) {
  std::vector<const AvbDescriptor*>* descriptors =
      reinterpret_cast<std::vector<const AvbDescriptor*>*>(user_data);
  descriptors->push_back(descriptor);
  return true;  // Keep iterating.
}

void AvbToolTest::AddHashFooterTest(bool sparse_image) {
  const size_t rootfs_size = 1028 * 1024;
  const size_t partition_size = 1536 * 1024;

  // Generate a 1028 KiB file with known content. Some content have
  // been arranged to ensure FILL_DATA segments in the sparse file.
  std::vector<uint8_t> rootfs;
  rootfs.resize(rootfs_size);
  for (size_t n = 0; n < rootfs_size; n++) {
    if ((n >= 5 * 1000 && n < 105 * 1000) ||
        (n >= 205 * 1000 && n < 305 * 1000) ||
        (n >= 505 * 1000 && n < 605 * 1000)) {
      rootfs[n] = uint8_t(n) & 0x03;
    } else {
      rootfs[n] = uint8_t(n);
    }
  }
  base::FilePath rootfs_path = testdir_.Append("rootfs.bin");
  EXPECT_EQ(rootfs_size,
            static_cast<const size_t>(
                base::WriteFile(rootfs_path,
                                reinterpret_cast<const char*>(rootfs.data()),
                                rootfs.size())));

  if (sparse_image) {
    EXPECT_COMMAND(0,
                   "mv %s %s.unsparse",
                   rootfs_path.value().c_str(),
                   rootfs_path.value().c_str());
    EXPECT_COMMAND(0,
                   "img2simg %s.unsparse %s",
                   rootfs_path.value().c_str(),
                   rootfs_path.value().c_str());
    EXPECT_COMMAND(0, "rm -f %s.unsparse", rootfs_path.value().c_str());
  }

  /* Do this twice to check that 'add_hash_footer' is idempotent. */
  for (int n = 0; n < 2; n++) {
    EXPECT_COMMAND(0,
                   "./avbtool add_hash_footer --salt d00df00d "
                   "--hash_algorithm sha256 --image %s "
                   "--partition_size %d --partition_name foobar "
                   "--algorithm SHA256_RSA2048 "
                   "--key test/data/testkey_rsa2048.pem",
                   rootfs_path.value().c_str(),
                   (int)partition_size);

    ASSERT_EQ(base::StringPrintf("Footer version:           1.0\n"
                                 "Image size:               1572864 bytes\n"
                                 "Original image size:      1052672 bytes\n"
                                 "VBMeta offset:            1052672\n"
                                 "VBMeta size:              1536 bytes\n"
                                 "--\n"
                                 "VBMeta image version:     1.0%s\n"
                                 "Header Block:             256 bytes\n"
                                 "Authentication Block:     576 bytes\n"
                                 "Auxiliary Block:          704 bytes\n"
                                 "Algorithm:                SHA256_RSA2048\n"
                                 "Rollback Index:           0\n"
                                 "Flags:                    0\n"
                                 "Descriptors:\n"
                                 "    Hash descriptor:\n"
                                 "      Image Size:            1052672 bytes\n"
                                 "      Hash Algorithm:        sha256\n"
                                 "      Partition Name:        foobar\n"
                                 "      Salt:                  d00df00d\n"
                                 "      Digest:                "
                                 "9a58cc996d405e08a1e00f96dbfe9104fedf41cb83b1f"
                                 "5e4ed357fbcf58d88d9\n",
                                 sparse_image ? " (Sparse)" : ""),
              InfoImage(rootfs_path));
  }

  if (sparse_image) {
    EXPECT_COMMAND(0,
                   "mv %s %s.sparse",
                   rootfs_path.value().c_str(),
                   rootfs_path.value().c_str());
    EXPECT_COMMAND(0,
                   "simg2img %s.sparse %s",
                   rootfs_path.value().c_str(),
                   rootfs_path.value().c_str());
    EXPECT_COMMAND(0, "rm -f %s.sparse", rootfs_path.value().c_str());
  }

  // Manually calculate the hash to check that it agrees with avbtool.
  AvbSHA256Ctx hasher_ctx;
  const uint8_t hasher_salt[4] = {0xd0, 0x0d, 0xf0, 0x0d};
  avb_sha256_init(&hasher_ctx);
  avb_sha256_update(&hasher_ctx, hasher_salt, 4);
  avb_sha256_update(&hasher_ctx, rootfs.data(), rootfs_size);
  uint8_t* hasher_digest = avb_sha256_final(&hasher_ctx);
  EXPECT_EQ("9a58cc996d405e08a1e00f96dbfe9104fedf41cb83b1f5e4ed357fbcf58d88d9",
            mem_to_hexstring(hasher_digest, AVB_SHA256_DIGEST_SIZE));

  // Now check that we can find the VBMeta block again from the footer.
  std::string part_data;
  ASSERT_TRUE(base::ReadFileToString(rootfs_path, &part_data));

  // Check footer contains correct data.
  AvbFooter f;
  EXPECT_NE(0,
            avb_footer_validate_and_byteswap(
                reinterpret_cast<const AvbFooter*>(
                    part_data.data() + part_data.size() - AVB_FOOTER_SIZE),
                &f));
  EXPECT_EQ(
      std::string(reinterpret_cast<const char*>(f.magic), AVB_FOOTER_MAGIC_LEN),
      AVB_FOOTER_MAGIC);
  EXPECT_EQ(AVB_FOOTER_MAJOR_VERSION, (int)f.version_major);
  EXPECT_EQ(AVB_FOOTER_MINOR_VERSION, (int)f.version_minor);
  EXPECT_EQ(1052672UL, f.original_image_size);
  EXPECT_EQ(1052672UL, f.vbmeta_offset);
  EXPECT_EQ(1536UL, f.vbmeta_size);

  // Check that the vbmeta image at |f.vbmeta_offset| checks out.
  const uint8_t* vbmeta_data =
      reinterpret_cast<const uint8_t*>(part_data.data() + f.vbmeta_offset);
  EXPECT_EQ(AVB_VBMETA_VERIFY_RESULT_OK,
            avb_vbmeta_image_verify(vbmeta_data, f.vbmeta_size, NULL, NULL));

  // Collect all descriptors.
  std::vector<const AvbDescriptor*> descriptors;
  avb_descriptor_foreach(
      vbmeta_data, f.vbmeta_size, collect_descriptors, &descriptors);

  // We should only have a single descriptor and it should be a
  // hash descriptor.
  EXPECT_EQ(1UL, descriptors.size());
  EXPECT_EQ(AVB_DESCRIPTOR_TAG_HASH, avb_be64toh(descriptors[0]->tag));
  AvbHashDescriptor d;
  EXPECT_NE(
      0,
      avb_hash_descriptor_validate_and_byteswap(
          reinterpret_cast<const AvbHashDescriptor*>(descriptors[0]), &d));
  EXPECT_EQ(1052672UL, d.image_size);
  EXPECT_EQ(6UL, d.partition_name_len);
  EXPECT_EQ(4UL, d.salt_len);
  EXPECT_EQ(32UL, d.digest_len);
  const uint8_t* desc_end = reinterpret_cast<const uint8_t*>(descriptors[0]) +
                            sizeof(AvbHashDescriptor);
  uint64_t o = 0;
  EXPECT_EQ("foobar",
            std::string(reinterpret_cast<const char*>(desc_end + o),
                        d.partition_name_len));
  o += d.partition_name_len;
  EXPECT_EQ("d00df00d", mem_to_hexstring(desc_end + o, d.salt_len));
  o += d.salt_len;
  EXPECT_EQ("9a58cc996d405e08a1e00f96dbfe9104fedf41cb83b1f5e4ed357fbcf58d88d9",
            mem_to_hexstring(desc_end + o, d.digest_len));

  // Check that the footer is correctly erased.
  EXPECT_COMMAND(
      0, "./avbtool erase_footer --image %s", rootfs_path.value().c_str());
  int64_t erased_footer_file_size;
  ASSERT_TRUE(base::GetFileSize(rootfs_path, &erased_footer_file_size));
  EXPECT_EQ(static_cast<size_t>(erased_footer_file_size), rootfs_size);
}

TEST_F(AvbToolTest, AddHashFooter) {
  AddHashFooterTest(false);
}

TEST_F(AvbToolTest, AddHashFooterSparse) {
  AddHashFooterTest(true);
}

static std::string RemoveLinesStartingWith(const std::string& str,
                                           const std::string& prefix) {
  std::vector<std::string> lines;
  std::string ret;

  lines = base::SplitString(
      str, "\n", base::KEEP_WHITESPACE, base::SPLIT_WANT_NONEMPTY);
  for (const std::string& line : lines) {
    if (!base::StartsWith(line, prefix, base::CompareCase::SENSITIVE)) {
      ret += line;
      ret += '\n';
    }
  }
  return ret;
}

TEST_F(AvbToolTest, AddHashFooterSparseWithHoleAtTheEnd) {
  const size_t partition_size = 10 * 1024 * 1024;
  const size_t metadata_size = 128 * 1024;

  // It's not enough to run img2simg on a file with a lot of zeroes at
  // the end since that will turn up as "Fill with value (for value =
  // 0x00000000)" and not "Don't care". Instead, use make_ext4fs for
  // this since it will put a big hole (e.g. "Don't care" chunk) at
  // the end.
  base::FilePath partition_path = testdir_.Append("partition.bin");
  EXPECT_COMMAND(0,
                 "make_ext4fs -s -L test -l %zd %s",
                 partition_size - metadata_size,
                 partition_path.value().c_str());

  EXPECT_COMMAND(0,
                 "./avbtool add_hash_footer --salt d00df00d "
                 "--hash_algorithm sha256 --image %s "
                 "--partition_size %d --partition_name foobar "
                 "--algorithm SHA256_RSA2048 "
                 "--key test/data/testkey_rsa2048.pem",
                 partition_path.value().c_str(),
                 (int)partition_size);

  // Since we may be using an arbritary version of make_ext4fs
  // (because of different branches) the contents of the resulting
  // disk image may slightly change. It's enough to just remove the
  // "Digest:" line from the output to work around this.
  std::string info =
      RemoveLinesStartingWith(InfoImage(partition_path), "      Digest:");
  ASSERT_EQ(
      "Footer version:           1.0\n"
      "Image size:               10485760 bytes\n"
      "Original image size:      10354688 bytes\n"
      "VBMeta offset:            10354688\n"
      "VBMeta size:              1536 bytes\n"
      "--\n"
      "VBMeta image version:     1.0 (Sparse)\n"
      "Header Block:             256 bytes\n"
      "Authentication Block:     576 bytes\n"
      "Auxiliary Block:          704 bytes\n"
      "Algorithm:                SHA256_RSA2048\n"
      "Rollback Index:           0\n"
      "Flags:                    0\n"
      "Descriptors:\n"
      "    Hash descriptor:\n"
      "      Image Size:            10354688 bytes\n"
      "      Hash Algorithm:        sha256\n"
      "      Partition Name:        foobar\n"
      "      Salt:                  d00df00d\n",
      info);

  EXPECT_COMMAND(0,
                 "mv %s %s.sparse",
                 partition_path.value().c_str(),
                 partition_path.value().c_str());
  EXPECT_COMMAND(0,
                 "simg2img %s.sparse %s",
                 partition_path.value().c_str(),
                 partition_path.value().c_str());
  EXPECT_COMMAND(0, "rm -f %s.sparse", partition_path.value().c_str());
}

void AvbToolTest::AddHashtreeFooterTest(bool sparse_image) {
  const size_t rootfs_size = 1028 * 1024;
  const size_t partition_size = 1536 * 1024;

  // Generate a 1028 KiB file with known content.
  std::vector<uint8_t> rootfs;
  rootfs.resize(rootfs_size);
  for (size_t n = 0; n < rootfs_size; n++)
    rootfs[n] = uint8_t(n);
  base::FilePath rootfs_path = testdir_.Append("rootfs.bin");
  EXPECT_EQ(rootfs_size,
            static_cast<const size_t>(
                base::WriteFile(rootfs_path,
                                reinterpret_cast<const char*>(rootfs.data()),
                                rootfs.size())));

  if (sparse_image) {
    EXPECT_COMMAND(0,
                   "mv %s %s.unsparse",
                   rootfs_path.value().c_str(),
                   rootfs_path.value().c_str());
    EXPECT_COMMAND(0,
                   "img2simg %s.unsparse %s",
                   rootfs_path.value().c_str(),
                   rootfs_path.value().c_str());
    EXPECT_COMMAND(0, "rm -f %s.unsparse", rootfs_path.value().c_str());
  }

  /* Do this twice to check that 'add_hashtree_footer' is idempotent. */
  for (int n = 0; n < 2; n++) {
    EXPECT_COMMAND(0,
                   "./avbtool add_hashtree_footer --salt d00df00d --image %s "
                   "--partition_size %d --partition_name foobar "
                   "--algorithm SHA256_RSA2048 "
                   "--key test/data/testkey_rsa2048.pem",
                   rootfs_path.value().c_str(),
                   (int)partition_size);

    ASSERT_EQ(base::StringPrintf("Footer version:           1.0\n"
                                 "Image size:               1572864 bytes\n"
                                 "Original image size:      1052672 bytes\n"
                                 "VBMeta offset:            1069056\n"
                                 "VBMeta size:              1600 bytes\n"
                                 "--\n"
                                 "VBMeta image version:     1.0%s\n"
                                 "Header Block:             256 bytes\n"
                                 "Authentication Block:     576 bytes\n"
                                 "Auxiliary Block:          768 bytes\n"
                                 "Algorithm:                SHA256_RSA2048\n"
                                 "Rollback Index:           0\n"
                                 "Flags:                    0\n"
                                 "Descriptors:\n"
                                 "    Hashtree descriptor:\n"
                                 "      Version of dm-verity:  1\n"
                                 "      Image Size:            1052672 bytes\n"
                                 "      Tree Offset:           1052672\n"
                                 "      Tree Size:             16384 bytes\n"
                                 "      Data Block Size:       4096 bytes\n"
                                 "      Hash Block Size:       4096 bytes\n"
                                 "      FEC num roots:         0\n"
                                 "      FEC offset:            0\n"
                                 "      FEC size:              0 bytes\n"
                                 "      Hash Algorithm:        sha1\n"
                                 "      Partition Name:        foobar\n"
                                 "      Salt:                  d00df00d\n"
                                 "      Root Digest:           "
                                 "e811611467dcd6e8dc4324e45f706c2bdd51db67\n",
                                 sparse_image ? " (Sparse)" : ""),
              InfoImage(rootfs_path));
  }

  if (sparse_image) {
    EXPECT_COMMAND(0,
                   "mv %s %s.sparse",
                   rootfs_path.value().c_str(),
                   rootfs_path.value().c_str());
    EXPECT_COMMAND(0,
                   "simg2img %s.sparse %s",
                   rootfs_path.value().c_str(),
                   rootfs_path.value().c_str());
    EXPECT_COMMAND(0, "rm -f %s.sparse", rootfs_path.value().c_str());
  }

  // To check that we generate the correct hashtree we can use
  // veritysetup(1) - another codebase for working with dm-verity
  // hashtrees - to verify it.
  //
  // If we don't want to impose the requirement of having the
  // veritysetup(1) command available on builders we can comment this
  // out.
  EXPECT_COMMAND(0,
                 "veritysetup --no-superblock --format=1 --hash=sha1 "
                 "--data-block-size=4096 --hash-block-size=4096 "
                 "--salt=d00df00d "
                 "--data-blocks=257 "
                 "--hash-offset=1052672 "
                 "verify "
                 "%s %s "
                 "e811611467dcd6e8dc4324e45f706c2bdd51db67",
                 rootfs_path.value().c_str(),
                 rootfs_path.value().c_str());

  // Now check that we can find the VBMeta block again from the footer.
  std::string part_data;
  ASSERT_TRUE(base::ReadFileToString(rootfs_path, &part_data));

  // Check footer contains correct data.
  AvbFooter f;
  EXPECT_NE(0,
            avb_footer_validate_and_byteswap(
                reinterpret_cast<const AvbFooter*>(
                    part_data.data() + part_data.size() - AVB_FOOTER_SIZE),
                &f));
  EXPECT_EQ(
      std::string(reinterpret_cast<const char*>(f.magic), AVB_FOOTER_MAGIC_LEN),
      AVB_FOOTER_MAGIC);
  EXPECT_EQ(AVB_FOOTER_MAJOR_VERSION, (int)f.version_major);
  EXPECT_EQ(AVB_FOOTER_MINOR_VERSION, (int)f.version_minor);
  EXPECT_EQ(1052672UL, f.original_image_size);
  EXPECT_EQ(1069056UL, f.vbmeta_offset);
  EXPECT_EQ(1600UL, f.vbmeta_size);

  // Check that the vbmeta image at |f.vbmeta_offset| checks out.
  const uint8_t* vbmeta_data =
      reinterpret_cast<const uint8_t*>(part_data.data() + f.vbmeta_offset);
  EXPECT_EQ(AVB_VBMETA_VERIFY_RESULT_OK,
            avb_vbmeta_image_verify(vbmeta_data, f.vbmeta_size, NULL, NULL));

  // Collect all descriptors.
  std::vector<const AvbDescriptor*> descriptors;
  avb_descriptor_foreach(
      vbmeta_data, f.vbmeta_size, collect_descriptors, &descriptors);

  // We should only have a single descriptor and it should be a
  // hashtree descriptor.
  EXPECT_EQ(1UL, descriptors.size());
  EXPECT_EQ(AVB_DESCRIPTOR_TAG_HASHTREE, avb_be64toh(descriptors[0]->tag));
  AvbHashtreeDescriptor d;
  EXPECT_NE(
      0,
      avb_hashtree_descriptor_validate_and_byteswap(
          reinterpret_cast<const AvbHashtreeDescriptor*>(descriptors[0]), &d));
  EXPECT_EQ(1UL, d.dm_verity_version);
  EXPECT_EQ(1052672UL, d.image_size);
  EXPECT_EQ(1052672UL, d.tree_offset);
  EXPECT_EQ(16384UL, d.tree_size);
  EXPECT_EQ(4096UL, d.data_block_size);
  EXPECT_EQ(4096UL, d.hash_block_size);
  EXPECT_EQ(6UL, d.partition_name_len);
  EXPECT_EQ(4UL, d.salt_len);
  EXPECT_EQ(20UL, d.root_digest_len);
  const uint8_t* desc_end = reinterpret_cast<const uint8_t*>(descriptors[0]) +
                            sizeof(AvbHashtreeDescriptor);
  uint64_t o = 0;
  EXPECT_EQ("foobar",
            std::string(reinterpret_cast<const char*>(desc_end + o),
                        d.partition_name_len));
  o += d.partition_name_len;
  EXPECT_EQ("d00df00d", mem_to_hexstring(desc_end + o, d.salt_len));
  o += d.salt_len;
  EXPECT_EQ("e811611467dcd6e8dc4324e45f706c2bdd51db67",
            mem_to_hexstring(desc_end + o, d.root_digest_len));

  // Check that we correctly generate dm-verity kernel cmdline
  // snippets, if requested.
  base::FilePath vbmeta_dmv_path = testdir_.Append("vbmeta_dm_verity_desc.bin");
  EXPECT_COMMAND(0,
                 "./avbtool make_vbmeta_image "
                 "--output %s "
                 "--generate_dm_verity_cmdline_from_hashtree %s "
                 "--algorithm SHA256_RSA2048 "
                 "--key test/data/testkey_rsa2048.pem",
                 vbmeta_dmv_path.value().c_str(),
                 rootfs_path.value().c_str());

  ASSERT_EQ(
      "VBMeta image version:     1.0\n"
      "Header Block:             256 bytes\n"
      "Authentication Block:     576 bytes\n"
      "Auxiliary Block:          896 bytes\n"
      "Algorithm:                SHA256_RSA2048\n"
      "Rollback Index:           0\n"
      "Flags:                    0\n"
      "Descriptors:\n"
      "    Kernel Cmdline descriptor:\n"
      "      Flags:                 1\n"
      "      Kernel Cmdline:        'dm=\"1 vroot none ro 1,0 2056 verity 1 "
      "PARTUUID=$(ANDROID_SYSTEM_PARTUUID) PARTUUID=$(ANDROID_SYSTEM_PARTUUID) "
      "4096 4096 257 257 sha1 e811611467dcd6e8dc4324e45f706c2bdd51db67 "
      "d00df00d 1 ignore_zero_blocks\" root=0xfd00 "
      "androidboot.vbmeta.device=PARTUUID=$(ANDROID_VBMETA_PARTUUID)'\n"
      "    Kernel Cmdline descriptor:\n"
      "      Flags:                 2\n"
      "      Kernel Cmdline:        "
      "'root=PARTUUID=$(ANDROID_SYSTEM_PARTUUID)'\n",
      InfoImage(vbmeta_dmv_path));

  // Check that the footer is correctly erased and the hashtree
  // remains - see above for why the constant 1069056 is used.
  EXPECT_COMMAND(0,
                 "./avbtool erase_footer --image %s --keep_hashtree",
                 rootfs_path.value().c_str());
  int64_t erased_footer_file_size;
  ASSERT_TRUE(base::GetFileSize(rootfs_path, &erased_footer_file_size));
  EXPECT_EQ(static_cast<size_t>(erased_footer_file_size), 1069056UL);
}

TEST_F(AvbToolTest, AddHashtreeFooter) {
  AddHashtreeFooterTest(false);
}

TEST_F(AvbToolTest, AddHashtreeFooterSparse) {
  AddHashtreeFooterTest(true);
}

void AvbToolTest::AddHashtreeFooterFECTest(bool sparse_image) {
  const size_t rootfs_size = 1028 * 1024;
  const size_t partition_size = 1536 * 1024;

  // Generate a 1028 KiB file with known content.
  std::vector<uint8_t> rootfs;
  rootfs.resize(rootfs_size);
  for (size_t n = 0; n < rootfs_size; n++)
    rootfs[n] = uint8_t(n);
  base::FilePath rootfs_path = testdir_.Append("rootfs.bin");
  EXPECT_EQ(rootfs_size,
            static_cast<const size_t>(
                base::WriteFile(rootfs_path,
                                reinterpret_cast<const char*>(rootfs.data()),
                                rootfs.size())));

  if (sparse_image) {
    EXPECT_COMMAND(0,
                   "mv %s %s.unsparse",
                   rootfs_path.value().c_str(),
                   rootfs_path.value().c_str());
    EXPECT_COMMAND(0,
                   "img2simg %s.unsparse %s",
                   rootfs_path.value().c_str(),
                   rootfs_path.value().c_str());
    EXPECT_COMMAND(0, "rm -f %s.unsparse", rootfs_path.value().c_str());
  }

  /* Do this twice to check that 'add_hashtree_footer' is idempotent. */
  for (int n = 0; n < 2; n++) {
    EXPECT_COMMAND(0,
                   "./avbtool add_hashtree_footer --salt d00df00d --image %s "
                   "--partition_size %d --partition_name foobar "
                   "--generate_fec "
                   "--algorithm SHA256_RSA2048 "
                   "--key test/data/testkey_rsa2048.pem",
                   rootfs_path.value().c_str(),
                   (int)partition_size);

    ASSERT_EQ(base::StringPrintf("Footer version:           1.0\n"
                                 "Image size:               1572864 bytes\n"
                                 "Original image size:      1052672 bytes\n"
                                 "VBMeta offset:            1085440\n"
                                 "VBMeta size:              1600 bytes\n"
                                 "--\n"
                                 "VBMeta image version:     1.0%s\n"
                                 "Header Block:             256 bytes\n"
                                 "Authentication Block:     576 bytes\n"
                                 "Auxiliary Block:          768 bytes\n"
                                 "Algorithm:                SHA256_RSA2048\n"
                                 "Rollback Index:           0\n"
                                 "Flags:                    0\n"
                                 "Descriptors:\n"
                                 "    Hashtree descriptor:\n"
                                 "      Version of dm-verity:  1\n"
                                 "      Image Size:            1052672 bytes\n"
                                 "      Tree Offset:           1052672\n"
                                 "      Tree Size:             16384 bytes\n"
                                 "      Data Block Size:       4096 bytes\n"
                                 "      Hash Block Size:       4096 bytes\n"
                                 "      FEC num roots:         2\n"
                                 "      FEC offset:            1069056\n"
                                 "      FEC size:              16384 bytes\n"
                                 "      Hash Algorithm:        sha1\n"
                                 "      Partition Name:        foobar\n"
                                 "      Salt:                  d00df00d\n"
                                 "      Root Digest:           "
                                 "e811611467dcd6e8dc4324e45f706c2bdd51db67\n",
                                 sparse_image ? " (Sparse)" : ""),
              InfoImage(rootfs_path));
  }

  if (sparse_image) {
    EXPECT_COMMAND(0,
                   "mv %s %s.sparse",
                   rootfs_path.value().c_str(),
                   rootfs_path.value().c_str());
    EXPECT_COMMAND(0,
                   "simg2img %s.sparse %s",
                   rootfs_path.value().c_str(),
                   rootfs_path.value().c_str());
    EXPECT_COMMAND(0, "rm -f %s.sparse", rootfs_path.value().c_str());
  }

  /* TODO: would be nice to verify that the FEC data is correct. */

  // Now check that we can find the VBMeta block again from the footer.
  std::string part_data;
  ASSERT_TRUE(base::ReadFileToString(rootfs_path, &part_data));

  // Check footer contains correct data.
  AvbFooter f;
  EXPECT_NE(0,
            avb_footer_validate_and_byteswap(
                reinterpret_cast<const AvbFooter*>(
                    part_data.data() + part_data.size() - AVB_FOOTER_SIZE),
                &f));
  EXPECT_EQ(
      std::string(reinterpret_cast<const char*>(f.magic), AVB_FOOTER_MAGIC_LEN),
      AVB_FOOTER_MAGIC);
  EXPECT_EQ(AVB_FOOTER_MAJOR_VERSION, (int)f.version_major);
  EXPECT_EQ(AVB_FOOTER_MINOR_VERSION, (int)f.version_minor);
  EXPECT_EQ(1052672UL, f.original_image_size);
  EXPECT_EQ(1085440UL, f.vbmeta_offset);
  EXPECT_EQ(1600UL, f.vbmeta_size);

  // Check that the vbmeta image at |f.vbmeta_offset| checks out.
  const uint8_t* vbmeta_data =
      reinterpret_cast<const uint8_t*>(part_data.data() + f.vbmeta_offset);
  EXPECT_EQ(AVB_VBMETA_VERIFY_RESULT_OK,
            avb_vbmeta_image_verify(vbmeta_data, f.vbmeta_size, NULL, NULL));

  // Collect all descriptors.
  std::vector<const AvbDescriptor*> descriptors;
  avb_descriptor_foreach(
      vbmeta_data, f.vbmeta_size, collect_descriptors, &descriptors);

  // We should only have a single descriptor and it should be a
  // hashtree descriptor.
  EXPECT_EQ(1UL, descriptors.size());
  EXPECT_EQ(AVB_DESCRIPTOR_TAG_HASHTREE, avb_be64toh(descriptors[0]->tag));
  AvbHashtreeDescriptor d;
  EXPECT_NE(
      0,
      avb_hashtree_descriptor_validate_and_byteswap(
          reinterpret_cast<const AvbHashtreeDescriptor*>(descriptors[0]), &d));
  EXPECT_EQ(1UL, d.dm_verity_version);
  EXPECT_EQ(1052672UL, d.image_size);
  EXPECT_EQ(1052672UL, d.tree_offset);
  EXPECT_EQ(16384UL, d.tree_size);
  EXPECT_EQ(4096UL, d.data_block_size);
  EXPECT_EQ(2UL, d.fec_num_roots);
  EXPECT_EQ(1069056UL, d.fec_offset);
  EXPECT_EQ(16384UL, d.fec_size);
  EXPECT_EQ(6UL, d.partition_name_len);
  EXPECT_EQ(4UL, d.salt_len);
  EXPECT_EQ(20UL, d.root_digest_len);
  const uint8_t* desc_end = reinterpret_cast<const uint8_t*>(descriptors[0]) +
                            sizeof(AvbHashtreeDescriptor);
  uint64_t o = 0;
  EXPECT_EQ("foobar",
            std::string(reinterpret_cast<const char*>(desc_end + o),
                        d.partition_name_len));
  o += d.partition_name_len;
  EXPECT_EQ("d00df00d", mem_to_hexstring(desc_end + o, d.salt_len));
  o += d.salt_len;
  EXPECT_EQ("e811611467dcd6e8dc4324e45f706c2bdd51db67",
            mem_to_hexstring(desc_end + o, d.root_digest_len));

  // Check that we correctly generate dm-verity kernel cmdline
  // snippets, if requested.
  base::FilePath vbmeta_dmv_path = testdir_.Append("vbmeta_dm_verity_desc.bin");
  EXPECT_COMMAND(0,
                 "./avbtool make_vbmeta_image "
                 "--output %s "
                 "--generate_dm_verity_cmdline_from_hashtree %s "
                 "--algorithm SHA256_RSA2048 "
                 "--key test/data/testkey_rsa2048.pem",
                 vbmeta_dmv_path.value().c_str(),
                 rootfs_path.value().c_str());

  ASSERT_EQ(
      "VBMeta image version:     1.0\n"
      "Header Block:             256 bytes\n"
      "Authentication Block:     576 bytes\n"
      "Auxiliary Block:          1024 bytes\n"
      "Algorithm:                SHA256_RSA2048\n"
      "Rollback Index:           0\n"
      "Flags:                    0\n"
      "Descriptors:\n"
      "    Kernel Cmdline descriptor:\n"
      "      Flags:                 1\n"
      "      Kernel Cmdline:        'dm=\"1 vroot none ro 1,0 2056 verity 1 "
      "PARTUUID=$(ANDROID_SYSTEM_PARTUUID) PARTUUID=$(ANDROID_SYSTEM_PARTUUID) "
      "4096 4096 257 257 sha1 e811611467dcd6e8dc4324e45f706c2bdd51db67 "
      "d00df00d 9 ignore_zero_blocks use_fec_from_device "
      "PARTUUID=$(ANDROID_SYSTEM_PARTUUID) fec_roots 2 fec_blocks 261 "
      "fec_start 261\" root=0xfd00 "
      "androidboot.vbmeta.device=PARTUUID=$(ANDROID_VBMETA_PARTUUID)'\n"
      "    Kernel Cmdline descriptor:\n"
      "      Flags:                 2\n"
      "      Kernel Cmdline:        "
      "'root=PARTUUID=$(ANDROID_SYSTEM_PARTUUID)'\n",
      InfoImage(vbmeta_dmv_path));

  // Check that the footer is correctly erased and the hashtree
  // remains - see above for why the constant 1069056 is used.
  EXPECT_COMMAND(0,
                 "./avbtool erase_footer --image %s --keep_hashtree",
                 rootfs_path.value().c_str());
  int64_t erased_footer_file_size;
  ASSERT_TRUE(base::GetFileSize(rootfs_path, &erased_footer_file_size));
  EXPECT_EQ(static_cast<size_t>(erased_footer_file_size), 1069056UL);
}

TEST_F(AvbToolTest, AddHashtreeFooterFEC) {
  AddHashtreeFooterFECTest(false);
}

TEST_F(AvbToolTest, AddHashtreeFooterFECSparse) {
  AddHashtreeFooterFECTest(true);
}

TEST_F(AvbToolTest, AddHashtreeFooterCalcMaxImageSize) {
  const size_t partition_size = 10 * 1024 * 1024;
  base::FilePath output_path = testdir_.Append("max_size.txt");

  EXPECT_COMMAND(0,
                 "./avbtool add_hashtree_footer "
                 "--partition_size %zd --calc_max_image_size > %s",
                 partition_size,
                 output_path.value().c_str());
  std::string max_image_size_data;
  EXPECT_TRUE(base::ReadFileToString(output_path, &max_image_size_data));
  EXPECT_EQ("10330112\n", max_image_size_data);
  size_t max_image_size = atoll(max_image_size_data.c_str());

  // Hashtree and metadata takes up 152 KiB - compare to below with
  // FEC which is 244 KiB.
  EXPECT_EQ(152 * 1024ULL, partition_size - max_image_size);

  // Check that we can add a hashtree with an image this size for such
  // a partition size.
  base::FilePath system_path = GenerateImage("system", max_image_size);
  EXPECT_COMMAND(0,
                 "./avbtool add_hashtree_footer"
                 " --image %s"
                 " --partition_name system"
                 " --partition_size %zd"
                 " --salt deadbeef"
                 " --algorithm SHA512_RSA4096 "
                 " --key test/data/testkey_rsa4096.pem",
                 system_path.value().c_str(),
                 partition_size);
}

TEST_F(AvbToolTest, AddHashtreeFooterCalcMaxImageSizeWithFEC) {
  const size_t partition_size = 10 * 1024 * 1024;
  base::FilePath output_path = testdir_.Append("max_size.txt");

  EXPECT_COMMAND(0,
                 "./avbtool add_hashtree_footer "
                 "--partition_size %zd --generate_fec "
                 "--calc_max_image_size > %s",
                 partition_size,
                 output_path.value().c_str());
  std::string max_image_size_data;
  EXPECT_TRUE(base::ReadFileToString(output_path, &max_image_size_data));
  EXPECT_EQ("10235904\n", max_image_size_data);
  size_t max_image_size = atoll(max_image_size_data.c_str());

  // Hashtree, FEC codes, and metadata takes up 244 KiB - compare to
  // above wihtout FEC which is 152 KiB.
  EXPECT_EQ(244 * 1024ULL, partition_size - max_image_size);

  // Check that we can add a hashtree with an image this size for such
  // a partition size.
  base::FilePath system_path = GenerateImage("system", max_image_size);
  EXPECT_COMMAND(0,
                 "./avbtool add_hashtree_footer"
                 " --image %s"
                 " --partition_name system"
                 " --partition_size %zd"
                 " --salt deadbeef"
                 " --generate_fec "
                 " --algorithm SHA512_RSA4096 "
                 " --key test/data/testkey_rsa4096.pem",
                 system_path.value().c_str(),
                 partition_size);
}

TEST_F(AvbToolTest, KernelCmdlineDescriptor) {
  base::FilePath vbmeta_path =
      testdir_.Append("vbmeta_kernel_cmdline_desc.bin");

  EXPECT_COMMAND(0,
                 "./avbtool make_vbmeta_image "
                 "--output %s "
                 "--kernel_cmdline 'foo bar baz' "
                 "--kernel_cmdline 'second cmdline' "
                 "--algorithm SHA256_RSA2048 "
                 "--key test/data/testkey_rsa2048.pem",
                 vbmeta_path.value().c_str());

  ASSERT_EQ(
      "VBMeta image version:     1.0\n"
      "Header Block:             256 bytes\n"
      "Authentication Block:     576 bytes\n"
      "Auxiliary Block:          640 bytes\n"
      "Algorithm:                SHA256_RSA2048\n"
      "Rollback Index:           0\n"
      "Flags:                    0\n"
      "Descriptors:\n"
      "    Kernel Cmdline descriptor:\n"
      "      Flags:                 0\n"
      "      Kernel Cmdline:        'foo bar baz'\n"
      "    Kernel Cmdline descriptor:\n"
      "      Flags:                 0\n"
      "      Kernel Cmdline:        'second cmdline'\n",
      InfoImage(vbmeta_path));

  // Now check the VBMeta image.
  std::string image_data;
  ASSERT_TRUE(base::ReadFileToString(vbmeta_path, &image_data));

  const uint8_t* vbmeta_data =
      reinterpret_cast<const uint8_t*>(image_data.data());
  const size_t vbmeta_size = image_data.length();
  EXPECT_EQ(AVB_VBMETA_VERIFY_RESULT_OK,
            avb_vbmeta_image_verify(vbmeta_data, vbmeta_size, NULL, NULL));

  // Collect all descriptors.
  std::vector<const AvbDescriptor*> descriptors;
  avb_descriptor_foreach(
      vbmeta_data, vbmeta_size, collect_descriptors, &descriptors);

  // We should have two descriptors - check them.
  EXPECT_EQ(2UL, descriptors.size());
  AvbKernelCmdlineDescriptor d;
  EXPECT_EQ(AVB_DESCRIPTOR_TAG_KERNEL_CMDLINE,
            avb_be64toh(descriptors[0]->tag));
  EXPECT_NE(
      0,
      avb_kernel_cmdline_descriptor_validate_and_byteswap(
          reinterpret_cast<const AvbKernelCmdlineDescriptor*>(descriptors[0]),
          &d));
  EXPECT_EQ("foo bar baz",
            std::string(reinterpret_cast<const char*>(descriptors[0]) +
                            sizeof(AvbKernelCmdlineDescriptor),
                        d.kernel_cmdline_length));
  EXPECT_EQ(AVB_DESCRIPTOR_TAG_KERNEL_CMDLINE,
            avb_be64toh(descriptors[1]->tag));
  EXPECT_NE(
      0,
      avb_kernel_cmdline_descriptor_validate_and_byteswap(
          reinterpret_cast<const AvbKernelCmdlineDescriptor*>(descriptors[1]),
          &d));
  EXPECT_EQ("second cmdline",
            std::string(reinterpret_cast<const char*>(descriptors[1]) +
                            sizeof(AvbKernelCmdlineDescriptor),
                        d.kernel_cmdline_length));
}

TEST_F(AvbToolTest, IncludeDescriptor) {
  base::FilePath vbmeta1_path = testdir_.Append("vbmeta_id1.bin");
  base::FilePath vbmeta2_path = testdir_.Append("vbmeta_id2.bin");
  base::FilePath vbmeta3_path = testdir_.Append("vbmeta_id3.bin");

  EXPECT_COMMAND(0,
                 "./avbtool make_vbmeta_image "
                 "--output %s "
                 "--kernel_cmdline 'something' "
                 "--prop name:value ",
                 vbmeta1_path.value().c_str());

  EXPECT_COMMAND(0,
                 "./avbtool make_vbmeta_image "
                 "--output %s "
                 "--prop name2:value2 "
                 "--prop name3:value3 ",
                 vbmeta2_path.value().c_str());

  EXPECT_COMMAND(0,
                 "./avbtool make_vbmeta_image "
                 "--output %s "
                 "--prop name4:value4 "
                 "--include_descriptors_from_image %s "
                 "--include_descriptors_from_image %s ",
                 vbmeta3_path.value().c_str(),
                 vbmeta1_path.value().c_str(),
                 vbmeta2_path.value().c_str());

  ASSERT_EQ(
      "VBMeta image version:     1.0\n"
      "Header Block:             256 bytes\n"
      "Authentication Block:     0 bytes\n"
      "Auxiliary Block:          256 bytes\n"
      "Algorithm:                NONE\n"
      "Rollback Index:           0\n"
      "Flags:                    0\n"
      "Descriptors:\n"
      "    Prop: name4 -> 'value4'\n"
      "    Prop: name -> 'value'\n"
      "    Kernel Cmdline descriptor:\n"
      "      Flags:                 0\n"
      "      Kernel Cmdline:        'something'\n"
      "    Prop: name2 -> 'value2'\n"
      "    Prop: name3 -> 'value3'\n",
      InfoImage(vbmeta3_path));
}

TEST_F(AvbToolTest, ChainedPartition) {
  base::FilePath vbmeta_path = testdir_.Append("vbmeta_cp.bin");

  base::FilePath pk_path = testdir_.Append("testkey_rsa2048.avbpubkey");

  EXPECT_COMMAND(
      0,
      "./avbtool extract_public_key --key test/data/testkey_rsa2048.pem"
      " --output %s",
      pk_path.value().c_str());

  EXPECT_COMMAND(
      0,
      "./avbtool make_vbmeta_image "
      "--output %s "
      "--chain_partition system:1:%s "
      "--algorithm SHA256_RSA2048 --key test/data/testkey_rsa2048.pem",
      vbmeta_path.value().c_str(),
      pk_path.value().c_str());

  ASSERT_EQ(
      "VBMeta image version:     1.0\n"
      "Header Block:             256 bytes\n"
      "Authentication Block:     576 bytes\n"
      "Auxiliary Block:          1152 bytes\n"
      "Algorithm:                SHA256_RSA2048\n"
      "Rollback Index:           0\n"
      "Flags:                    0\n"
      "Descriptors:\n"
      "    Chain Partition descriptor:\n"
      "      Partition Name:          system\n"
      "      Rollback Index Location: 1\n"
      "      Public key (sha1):       "
      "cdbb77177f731920bbe0a0f94f84d9038ae0617d\n",
      InfoImage(vbmeta_path));

  // Now check the VBMeta image.
  std::string image_data;
  ASSERT_TRUE(base::ReadFileToString(vbmeta_path, &image_data));

  const uint8_t* vbmeta_data =
      reinterpret_cast<const uint8_t*>(image_data.data());
  const size_t vbmeta_size = image_data.length();
  EXPECT_EQ(AVB_VBMETA_VERIFY_RESULT_OK,
            avb_vbmeta_image_verify(vbmeta_data, vbmeta_size, NULL, NULL));

  // Collect all descriptors.
  std::vector<const AvbDescriptor*> descriptors;
  avb_descriptor_foreach(
      vbmeta_data, vbmeta_size, collect_descriptors, &descriptors);

  // We should have one descriptor - check it.
  EXPECT_EQ(1UL, descriptors.size());

  std::string pk_data;
  ASSERT_TRUE(base::ReadFileToString(pk_path, &pk_data));

  AvbChainPartitionDescriptor d;
  EXPECT_EQ(AVB_DESCRIPTOR_TAG_CHAIN_PARTITION,
            avb_be64toh(descriptors[0]->tag));
  EXPECT_NE(
      0,
      avb_chain_partition_descriptor_validate_and_byteswap(
          reinterpret_cast<const AvbChainPartitionDescriptor*>(descriptors[0]),
          &d));
  const uint8_t* desc_end = reinterpret_cast<const uint8_t*>(descriptors[0]) +
                            sizeof(AvbChainPartitionDescriptor);
  uint64_t o = 0;
  EXPECT_EQ("system",
            std::string(reinterpret_cast<const char*>(desc_end + o),
                        d.partition_name_len));
  o += d.partition_name_len;
  EXPECT_EQ(pk_data,
            std::string(reinterpret_cast<const char*>(descriptors[0]) +
                            sizeof(AvbChainPartitionDescriptor) + o,
                        d.public_key_len));
}

TEST_F(AvbToolTest, SigningHelperBasic) {
  base::FilePath vbmeta_path = testdir_.Append("vbmeta.bin");
  base::FilePath signing_helper_test_path =
      testdir_.Append("signing_helper_test");
  EXPECT_COMMAND(
      0,
      "SIGNING_HELPER_TEST=\"%s\" ./avbtool make_vbmeta_image "
      "--output %s "
      "--algorithm SHA256_RSA2048 --key test/data/testkey_rsa2048.pem "
      "--signing_helper test/avbtool_signing_helper_test.py",
      signing_helper_test_path.value().c_str(),
      vbmeta_path.value().c_str());

  // Now check the value in test file.
  std::string value;
  ASSERT_TRUE(base::ReadFileToString(signing_helper_test_path, &value));
  EXPECT_EQ("DONE", value);
}

TEST_F(AvbToolTest, SigningHelperReturnError) {
  base::FilePath vbmeta_path = testdir_.Append("vbmeta.bin");
  EXPECT_COMMAND(
      1,
      "./avbtool make_vbmeta_image "
      "--output %s "
      "--algorithm SHA256_RSA2048 --key test/data/testkey_rsa2048.pem "
      "--signing_helper test/avbtool_signing_helper_test.py",
      vbmeta_path.value().c_str());
}

}  // namespace avb
