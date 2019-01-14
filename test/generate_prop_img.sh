#!/bin/bash

#
# Copyright (C) 2016 The Android Open Source Project
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation
# files (the "Software"), to deal in the Software without
# restriction, including without limitation the rights to use, copy,
# modify, merge, publish, distribute, sublicense, and/or sell copies
# of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#

# This script generates data/prop.img for avbtool_unittest.

if [ -z $(which mkuserimg_mke2fs) ]; then
    echo "mkuserimg_mke2fs is not available."
    exit 1
fi

mkdir -p data/prop_img/system
echo "
ro.build.version.security_patch=2018-12-05
# ro.build.version.security_patch=2018-11-05
" > data/prop_img/system/build.prop

mkuserimg_mke2fs data/prop_img data/prop.img ext4 / 409600 --android_sparse

rm -rf data/prop_img/

