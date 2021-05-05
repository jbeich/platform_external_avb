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

#include <gtest/gtest.h>
#include <libavb/avb_ed25519.h>
#include <libavb/avb_hkdf.h>
#include <libavb/avb_sha.h>
#include <string.h>

#include "avb_unittest_util.h"

namespace avb {

/* These smoke tests are intended to check that the cryptographic operations
 * conform to the AVB interface and not to check the correctness of the
 * cryptograhpy.
 */

TEST(CryptoOpsTest, Sha256) {
  AvbSHA256Ctx ctx;

  /* Compare with
   *
   * $ echo -n foobar |sha256sum
   * c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2 -
   */
  avb_sha256_init(&ctx);
  avb_sha256_update(&ctx, (const uint8_t*)"foobar", 6);
  EXPECT_EQ("c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2",
            mem_to_hexstring(avb_sha256_final(&ctx), AVB_SHA256_DIGEST_SIZE));
}

// Disabled for now because it takes ~30 seconds to run.
TEST(CryptoOpsTest, DISABLED_Sha256Large) {
  AvbSHA256Ctx ctx;

  /* Also check we this works with greater than 4GiB input. Compare with
   *
   * $ dd if=/dev/zero bs=1048576 count=4097 |sha256sum
   * 829816e339ff597ec3ada4c30fc840d3f2298444169d242952a54bcf3fcd7747 -
   */
  const size_t kMebibyte = 1048576;
  uint8_t* megabuf;
  megabuf = new uint8_t[kMebibyte];
  memset((char*)megabuf, '\0', kMebibyte);
  avb_sha256_init(&ctx);
  for (size_t n = 0; n < 4097; n++) {
    avb_sha256_update(&ctx, megabuf, kMebibyte);
  }
  EXPECT_EQ("829816e339ff597ec3ada4c30fc840d3f2298444169d242952a54bcf3fcd7747",
            mem_to_hexstring(avb_sha256_final(&ctx), AVB_SHA256_DIGEST_SIZE));
  delete[] megabuf;
}

TEST(CryptoOpsTest, Sha512) {
  AvbSHA512Ctx ctx;

  /* Compare with
   *
   * $ echo -n foobar |sha512sum
   * 0a50261ebd1a390fed2bf326f2673c145582a6342d523204973d0219337f81616a8069b012587cf5635f6925f1b56c360230c19b273500ee013e030601bf2425
   * -
   */
  avb_sha512_init(&ctx);
  avb_sha512_update(&ctx, (const uint8_t*)"foobar", 6);
  EXPECT_EQ(
      "0a50261ebd1a390fed2bf326f2673c145582a6342d523204973d0219337f81616a8069b0"
      "12587cf5635f6925f1b56c360230c19b273500ee013e030601bf2425",
      mem_to_hexstring(avb_sha512_final(&ctx), AVB_SHA512_DIGEST_SIZE));
}

// Disabled for now because it takes ~30 seconds to run.
TEST(CryptoOpsTest, DISABLED_Sha512Large) {
  AvbSHA512Ctx ctx;

  /* Also check we this works with greater than 4GiB input. Compare with
   *
   * $ dd if=/dev/zero bs=1048576 count=4097 |sha512sum
   * eac1685671cc2060315888746de072398116c0c83b7ee9463f0576e11bfdea9cdd5ddbf291fb3ffc4ee8a1b459c798d9fb9b50b7845e2871c4b1402470aaf4c0
   * -
   */
  const size_t kMebibyte = 1048576;
  uint8_t* megabuf;
  megabuf = new uint8_t[kMebibyte];
  memset((char*)megabuf, '\0', kMebibyte);
  avb_sha512_init(&ctx);
  for (size_t n = 0; n < 4097; n++) {
    avb_sha512_update(&ctx, megabuf, kMebibyte);
  }
  EXPECT_EQ(
      "eac1685671cc2060315888746de072398116c0c83b7ee9463f0576e11bfdea9cdd5ddbf2"
      "91fb3ffc4ee8a1b459c798d9fb9b50b7845e2871c4b1402470aaf4c0",
      mem_to_hexstring(avb_sha512_final(&ctx), AVB_SHA512_DIGEST_SIZE));
  delete[] megabuf;
}

TEST(CryptoOpsTest, HkdfSha512Rfc4231Test1) {
  uint8_t output[64];
  auto ikm = hexstring_to_mem(
      "a4326bc6723fae442f2463c26bc6344509asb8324ef89a7acb78ddd879820ac1");
  auto salt = hexstring_to_mem(
      "42b231c21c213cf12f1a1e2f12c31209903948109aabc8927effadaf283792fb");

  EXPECT_TRUE(avb_hkdf_sha512(output,
                              sizeof(output),
                              ikm.data(),
                              ikm.size(),
                              salt.data(),
                              salt.size(),
                              (const uint8_t*)"Test",
                              4));
  EXPECT_EQ(
      "64c9120be7278a02c7f94bb3327edb0cb8ebd7d343f6acc330743c29369901f5d2b5a80d"
      "bc7a116eae97fcccb3d788073f254b4d3f6e03daf8fe46faef2422b8",
      mem_to_hexstring(output, sizeof(output)));
}

TEST(CryptoOpsTest, HkdfSha512With128ByteOutput) {
  uint8_t output[128];
  auto ikm = hexstring_to_mem(
      "123b213f123c12f121d1a2311cf978b987ca897d987e234bafe617abcf23919c");
  auto salt = hexstring_to_mem("0123456789abcdef");

  EXPECT_TRUE(avb_hkdf_sha512(output,
                              sizeof(output),
                              ikm.data(),
                              ikm.size(),
                              salt.data(),
                              salt.size(),
                              (const uint8_t*)"Trial",
                              5));
  EXPECT_EQ(
      "7344a26ec33484da9492e4ffed13014839659b249dc1d5df9e8f86263497a4d0e3e8b98e"
      "4c126fecb36de01b2c21c13d70de855b488a10dd58539962580ab7fa28fb3b8f00c9be52"
      "222d62d301440eac2638bc40952efc59a507ce638569f1b4dc8d600c4cc2b6c90c608716"
      "e57dc686d37bdbf16071ab9f2984237b6ced8583",
      mem_to_hexstring(output, sizeof(output)));
}

TEST(CryptoOpsTest, HkdfSha512WithOutputTooLong) {
  std::vector<uint8_t> output(64000);
  auto ikm = hexstring_to_mem(
      "a4326bc6723fae442f2463c26bc6344509asb8324ef89a7acb78ddd879820ac1");
  auto salt = hexstring_to_mem(
      "42b231c21c213cf12f1a1e2f12c31209903948109aabc8927effadaf283792fb");

  EXPECT_FALSE(avb_hkdf_sha512(output.data(),
                               output.size(),
                               ikm.data(),
                               ikm.size(),
                               salt.data(),
                               salt.size(),
                               (const uint8_t*)"Test",
                               4));
}

TEST(CryptoOpsTest, Ed25516Rfc8032Test1) {
  auto secret = hexstring_to_mem(
      "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
  uint8_t public_key[32];
  uint8_t private_key[64];
  uint8_t signature[64];

  avb_ed25519_keypair_from_seed(public_key, private_key, secret.data());
  EXPECT_EQ("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            mem_to_hexstring(public_key, 32));

  EXPECT_TRUE(avb_ed25519_sign(signature, nullptr, 0, private_key));
  EXPECT_EQ(
      "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb88215"
      "90a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
      mem_to_hexstring(signature, 64));

  EXPECT_TRUE(avb_ed25519_verify(nullptr, 0, signature, public_key));
}

TEST(CryptoOpsTest, Ed25516Rfc8032Test2) {
  auto secret = hexstring_to_mem(
      "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");
  auto message = hexstring_to_mem("72");
  uint8_t public_key[32];
  uint8_t private_key[64];
  uint8_t signature[64];

  avb_ed25519_keypair_from_seed(public_key, private_key, secret.data());
  EXPECT_EQ("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            mem_to_hexstring(public_key, 32));

  EXPECT_TRUE(
      avb_ed25519_sign(signature, message.data(), message.size(), private_key));
  EXPECT_EQ(
      "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e4"
      "3e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
      mem_to_hexstring(signature, 64));

  EXPECT_TRUE(avb_ed25519_verify(
      message.data(), message.size(), signature, public_key));
}

TEST(CryptoOpsTest, Ed25516Rfc8032Test3) {
  auto secret = hexstring_to_mem(
      "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7");
  auto message = hexstring_to_mem("af82");
  uint8_t public_key[32];
  uint8_t private_key[64];
  uint8_t signature[64];

  avb_ed25519_keypair_from_seed(public_key, private_key, secret.data());
  EXPECT_EQ("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
            mem_to_hexstring(public_key, 32));

  EXPECT_TRUE(
      avb_ed25519_sign(signature, message.data(), message.size(), private_key));
  EXPECT_EQ(
      "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b53"
      "8d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
      mem_to_hexstring(signature, 64));

  EXPECT_TRUE(avb_ed25519_verify(
      message.data(), message.size(), signature, public_key));
}

TEST(CryptoOpsTest, Ed25516Rfc8032Test1024) {
  auto secret = hexstring_to_mem(
      "f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5");
  auto message = hexstring_to_mem(
      "08b8b2b733424243760fe426a4b54908632110a66c2f6591eabd3345e3e4eb98fa6e264b"
      "f09efe12ee50f8f54e9f77b1e355f6c50544e23fb1433ddf73be84d879de7c0046dc4996"
      "d9e773f4bc9efe5738829adb26c81b37c93a1b270b20329d658675fc6ea534e0810a4432"
      "826bf58c941efb65d57a338bbd2e26640f89ffbc1a858efcb8550ee3a5e1998bd177e93a"
      "7363c344fe6b199ee5d02e82d522c4feba15452f80288a821a579116ec6dad2b3b310da9"
      "03401aa62100ab5d1a36553e06203b33890cc9b832f79ef80560ccb9a39ce767967ed628"
      "c6ad573cb116dbefefd75499da96bd68a8a97b928a8bbc103b6621fcde2beca1231d206b"
      "e6cd9ec7aff6f6c94fcd7204ed3455c68c83f4a41da4af2b74ef5c53f1d8ac70bdcb7ed1"
      "85ce81bd84359d44254d95629e9855a94a7c1958d1f8ada5d0532ed8a5aa3fb2d17ba70e"
      "b6248e594e1a2297acbbb39d502f1a8c6eb6f1ce22b3de1a1f40cc24554119a831a9aad6"
      "079cad88425de6bde1a9187ebb6092cf67bf2b13fd65f27088d78b7e883c8759d2c4f5c6"
      "5adb7553878ad575f9fad878e80a0c9ba63bcbcc2732e69485bbc9c90bfbd62481d9089b"
      "eccf80cfe2df16a2cf65bd92dd597b0707e0917af48bbb75fed413d238f5555a7a569d80"
      "c3414a8d0859dc65a46128bab27af87a71314f318c782b23ebfe808b82b0ce26401d2e22"
      "f04d83d1255dc51addd3b75a2b1ae0784504df543af8969be3ea7082ff7fc9888c144da2"
      "af58429ec96031dbcad3dad9af0dcbaaaf268cb8fcffead94f3c7ca495e056a9b47acdb7"
      "51fb73e666c6c655ade8297297d07ad1ba5e43f1bca32301651339e22904cc8c42f58c30"
      "c04aafdb038dda0847dd988dcda6f3bfd15c4b4c4525004aa06eeff8ca61783aacec57fb"
      "3d1f92b0fe2fd1a85f6724517b65e614ad6808d6f6ee34dff7310fdc82aebfd904b01e1d"
      "c54b2927094b2db68d6f903b68401adebf5a7e08d78ff4ef5d63653a65040cf9bfd4aca7"
      "984a74d37145986780fc0b16ac451649de6188a7dbdf191f64b5fc5e2ab47b57f7f7276c"
      "d419c17a3ca8e1b939ae49e488acba6b965610b5480109c8b17b80e1b7b750dfc7598d5d"
      "5011fd2dcc5600a32ef5b52a1ecc820e308aa342721aac0943bf6686b64b2579376504cc"
      "c493d97e6aed3fb0f9cd71a43dd497f01f17c0e2cb3797aa2a2f256656168e6c496afc5f"
      "b93246f6b1116398a346f1a641f3b041e989f7914f90cc2c7fff357876e506b50d334ba7"
      "7c225bc307ba537152f3f1610e4eafe595f6d9d90d11faa933a15ef1369546868a7f3a45"
      "a96768d40fd9d03412c091c6315cf4fde7cb68606937380db2eaaa707b4c4185c32eddcd"
      "d306705e4dc1ffc872eeee475a64dfac86aba41c0618983f8741c5ef68d3a101e8a3b8ca"
      "c60c905c15fc910840b94c00a0b9d0");
  uint8_t public_key[32];
  uint8_t private_key[64];
  uint8_t signature[64];

  avb_ed25519_keypair_from_seed(public_key, private_key, secret.data());
  EXPECT_EQ("278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e",
            mem_to_hexstring(public_key, 32));

  EXPECT_TRUE(
      avb_ed25519_sign(signature, message.data(), message.size(), private_key));
  EXPECT_EQ(
      "0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fec350aa5371b1"
      "508f9f4528ecea23c436d94b5e8fcd4f681e30a6ac00a9704a188a03",
      mem_to_hexstring(signature, 64));

  EXPECT_TRUE(avb_ed25519_verify(
      message.data(), message.size(), signature, public_key));
}

TEST(CryptoOpsTest, Ed25516VerifyRejection) {
  auto secret = hexstring_to_mem(
      "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7");
  auto message = hexstring_to_mem("af82");
  uint8_t public_key[32];
  uint8_t private_key[64];
  uint8_t signature[64];

  avb_ed25519_keypair_from_seed(public_key, private_key, secret.data());
  EXPECT_EQ("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
            mem_to_hexstring(public_key, 32));

  EXPECT_TRUE(
      avb_ed25519_sign(signature, message.data(), message.size(), private_key));
  EXPECT_EQ(
      "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b53"
      "8d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
      mem_to_hexstring(signature, 64));

  EXPECT_FALSE(avb_ed25519_verify(
      message.data(), message.size(), signature, secret.data()));
}

}  // namespace avb
