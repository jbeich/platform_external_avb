// Copyright 2024, The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! libavb_hash support.

use crate::IoResult;
use avb_bindgen::AvbDigestType;

/// `AvbDigestType` wrapper.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HashType {
    /// `AvbDigestType.AVB_DIGEST_TYPE_SHA256`
    Sha256,
    /// `AvbDigestType.AVB_DIGEST_TYPE_SHA512`
    Sha512,
}

impl From<HashType> for AvbDigestType {
    fn from(hash_type: HashType) -> Self {
        match hash_type {
            HashType::Sha256 => AvbDigestType::AVB_DIGEST_TYPE_SHA256,
            HashType::Sha512 => AvbDigestType::AVB_DIGEST_TYPE_SHA512,
        }
    }
}

impl From<AvbDigestType> for HashType {
    fn from(digest_type: AvbDigestType) -> Self {
        match digest_type {
            AvbDigestType::AVB_DIGEST_TYPE_SHA256 => HashType::Sha256,
            AvbDigestType::AVB_DIGEST_TYPE_SHA512 => HashType::Sha512,
        }
    }
}

/// TODO
pub trait HashOps {
    /// TODO
    fn init(&mut self, hash_type: HashType) -> IoResult<()>;

    /// TODO
    fn update(&mut self, data: &[u8]) -> IoResult<()>;

    /// TODO
    fn finalize(&mut self) -> IoResult<&[u8]>;
}
