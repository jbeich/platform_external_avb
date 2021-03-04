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

#include <openssl/sha.h>

#include "avb_unittest_util.h"
#include "fake_avb_ops.h"

namespace avb {

class AvbOpenDiceTest : public BaseAvbToolTest,
                        public FakeAvbOpsDelegateWithDefaults {
 public:
  AvbOpenDiceTest() {}

  virtual void SetUp() override {
    BaseAvbToolTest::SetUp();
    ops_.set_delegate(this);
    ops_.set_partition_dir(testdir_);
    ops_.set_stored_rollback_indexes({{0, 0}, {1, 0}, {2, 0}, {3, 0}});
    ops_.set_stored_is_device_unlocked(false);
  }
};

TEST_F(AvbOpenDiceTest, Basic) {
  GenerateVBMetaImage("vbmeta_a.img",
                      "SHA256_RSA2048",
                      0,
                      base::FilePath("test/data/testkey_rsa2048.pem"),
                      "--internal_release_string \"\"");

  std::string expected_public_key =
      PublicKeyAVB(base::FilePath("test/data/testkey_rsa2048.pem"));
  ops_.set_expected_public_key(expected_public_key);

  AvbSlotVerifyData* slot_data = NULL;
  const char* requested_partitions[] = {"boot", NULL};
  EXPECT_EQ(AVB_SLOT_VERIFY_RESULT_OK,
            avb_slot_verify(ops_.avb_ops(),
                            requested_partitions,
                            "_a",
                            AVB_SLOT_VERIFY_FLAGS_NONE,
                            AVB_HASHTREE_ERROR_MODE_RESTART_AND_INVALIDATE,
                            &slot_data));
  EXPECT_NE(nullptr, slot_data);

  uint8_t authority_hash[AVB_SHA256_DIGEST_SIZE];
  SHA256_CTX ctx;
  SHA256_Init(&ctx);
  SHA256_Update(&ctx, expected_public_key.data(), expected_public_key.size());
  SHA256_Final(authority_hash, &ctx);

  AvbOpenDiceData* dice_data;
  const uint8_t cdi_attest[AVB_OPEN_DICE_CDI_SIZE] = {0};
  const uint8_t cdi_seal[AVB_OPEN_DICE_CDI_SIZE] = {0};
  const uint8_t secret[AVB_OPEN_DICE_SECRET_SIZE] = {0};
  EXPECT_EQ(AVB_OPEN_DICE_RESULT_OK,
            avb_open_dice_generate(ops_.avb_open_dice_ops(),
                                   cdi_attest,
                                   cdi_seal,
                                   AVB_OPEN_DICE_BOOT_STATE_VERIFIED,
                                   authority_hash,
                                   secret,
                                   slot_data,
                                   &dice_data));
  EXPECT_NE(nullptr, dice_data);

  avb_slot_verify_data_free(slot_data);
  avb_open_dice_data_free(ops_.avb_open_dice_ops(), dice_data);
}

}  // namespace avb
