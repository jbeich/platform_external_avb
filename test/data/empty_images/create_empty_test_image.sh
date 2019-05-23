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
# This script create an empty test image that has valid vbmeta footer. The test
# image would be used in AVB tests to act as an invalid image.
# The original image size would be 400KB which should be small enough to fit
# in any partition. The image with vbmeta footer would be 500KB.
# Run this script in Android tree after running
# 'make avbtool'
# and
# 'make mkuserimg_mke2fs'
#
set -e

if [[ -z "${ANDROID_BUILD_TOP}" ]]; then
  echo "Please lunch under Android repo before running this script."
  exit -1
fi

IMAGES=(system oem vendor boot)
AVB_DIR="${ANDROID_BUILD_TOP}/external/avb"
AVBTOOL="${AVB_DIR}/avbtool"
OUTPUT_DIR="${AVB_DIR}/test/data/empty_images"


for image in "${IMAGES[@]}"; do
  rm -rf empty
  if [[ "${image}" == "boot" ]]; then
    touch empty
    python "${ANDROID_BUILD_TOP}"/system/core/mkbootimg/mkbootimg.py --kernel empty -o "${OUTPUT_DIR}/${image}.img"
  else
    mkdir -p empty
    mkuserimg_mke2fs empty "${OUTPUT_DIR}/${image}.img" ext4 "${image}" 409600 -D /tmp/empty
  fi
  avbtool add_hash_footer --partition_name "${image}" --partition_size 512000 --image "${OUTPUT_DIR}/${image}.img"
  rm -rf empty
done

echo "All test empty partitions generated!"
