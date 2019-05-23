#!/bin/bash
#
# Copyright (C) 2019 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# This script create an multiple vbmeta images to be used as initial corpus for
# avb_slot_verify_vbmeta fuzzing test.

set -e

if [[ -z "${ANDROID_BUILD_TOP}" ]]; then
  echo "Please lunch under Android repo before running this script."
  exit -1
fi

AVB_DIR="${ANDROID_BUILD_TOP}/external/avb"
AVBTOOL="${AVB_DIR}/avbtool"
DATA_DIR="${AVB_DIR}/test/data"
OUTPUT_DIR="${DATA_DIR}/vbmeta"

AlgorithmAndKey="--algorithm SHA512_RSA4096  --key ${DATA_DIR}/testkey_atx_psk.pem"
PublicKey="--public_key_metadata ${DATA_DIR}/atx_metadata.bin"

${AVBTOOL} make_vbmeta_image --output ${OUTPUT_DIR}/test_vbmeta.img

${AVBTOOL} make_vbmeta_image --padding_size 5 --output ${OUTPUT_DIR}/test_vbmeta_padding_size_5.img

${AVBTOOL} make_vbmeta_image --padding_size 8 --output ${OUTPUT_DIR}/test_vbmeta_padding_size_8.img


${AVBTOOL} make_vbmeta_image ${AlgorithmAndKey} --output ${OUTPUT_DIR}/test_vbmeta_key.img

${AVBTOOL} make_vbmeta_image ${AlgorithmAndKey} ${PublicKey} --output ${OUTPUT_DIR}/test_vbmeta_key_metadata.img

${AVBTOOL} make_vbmeta_image ${AlgorithmAndKey} ${PublicKey} \
  --prop foo:brillo --prop bar:chromeos --prop prisoner:24601 --prop hexnumber:0xcafe \
  --prop hexnumber_capital:0xCAFE --prop large_hexnumber:0xfedcba9876543210 \
  --prop larger_than_uint64:0xfedcba98765432101 --prop almost_a_number:423x \
  --prop_from_file blob:${DATA_DIR}/small_blob.bin --prop_from_file large_blob:${DATA_DIR}/large_blob.bin \
  --output ${OUTPUT_DIR}/test_vbmeta_prop.img

${AVBTOOL} make_vbmeta_image ${AlgorithmAndKey} ${PublicKey} --rollback_index 1 --output ${OUTPUT_DIR}/test_vbmeta_rollback_1.img

${AVBTOOL} make_vbmeta_image ${AlgorithmAndKey} ${PublicKey} --append_to_release_string "a" --output ${OUTPUT_DIR}/test_vbmeta_release_string.img

${AVBTOOL} make_vbmeta_image ${AlgorithmAndKey} ${PublicKey} --kernel_cmdline "a=b=c" --output ${OUTPUT_DIR}/test_vbmeta_kernel_cmdline.img

${AVBTOOL} make_vbmeta_image ${AlgorithmAndKey} ${PublicKey} --flags 1 --output ${OUTPUT_DIR}/test_vbmeta_flags_1.img

${AVBTOOL} make_vbmeta_image ${AlgorithmAndKey} ${PublicKey} --set_hashtree_disabled_flag --output ${OUTPUT_DIR}/test_vbmeta_hashtree_disabled.img

# TODO include_descriptors_from_image, chain_partition
${AVBTOOL} make_vbmeta_image ${AlgorithmAndKey} ${PublicKey} \
  --include_descriptors_from_image ${DATA_DIR}/empty_images/boot.img \
  --include_descriptors_from_image ${DATA_DIR}/empty_images/oem.img \
  --include_descriptors_from_image ${DATA_DIR}/empty_images/system.img \
  --include_descriptors_from_image ${DATA_DIR}/empty_images/vendor.img \
  --output ${OUTPUT_DIR}/test_vbmeta_descriptors.img

${AVBTOOL} make_vbmeta_image ${AlgorithmAndKey} ${PublicKey} \
  --chain_partition system:1:${DATA_DIR}/testkey_rsa4096.pem \
  --output ${OUTPUT_DIR}/test_vbmeta_chain_partition.img

echo "All test vbmeta images generated!"
