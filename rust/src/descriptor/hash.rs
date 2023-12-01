// Copyright 2023, The Android Open Source Project
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

//! Hash descriptors.

use super::{
    util::{parse_descriptor, split_slice, ValidateAndByteswap, ValidationFunc},
    DescriptorError, DescriptorResult,
};
use avb_bindgen::{avb_hash_descriptor_validate_and_byteswap, AvbHashDescriptor};
use core::{ffi::CStr, str::from_utf8};

/// `AvbHashDescriptorFlags`; see libavb docs for details.
pub use avb_bindgen::AvbHashDescriptorFlags as HashDescriptorFlags;

/// Wraps a Hash descriptor stored in a vbmeta image.
#[derive(Debug, PartialEq, Eq)]
pub struct HashDescriptor<'a> {
    /// The size of the hashed image.
    pub image_size: u64,

    /// Hash algorithm name.
    pub hash_algorithm: &'a str,

    /// Flags.
    pub flags: HashDescriptorFlags,

    /// Partition name.
    ///
    /// Most partition names in this library are passed as `&CStr`, but inside
    /// descriptors the partition names are not nul-terminated making them
    /// ineligible for use directly as `&CStr`. If `&CStr` is required, one
    /// option is to allocate a nul-terminated copy of this string via
    /// `CString::new()` which can then be converted to `&CStr`.
    pub partition_name: &'a str,

    /// Salt used to hash the image.
    pub salt: &'a [u8],

    /// Image hash digest.
    pub digest: &'a [u8],
}

impl ValidateAndByteswap for AvbHashDescriptor {
    const VALIDATE_AND_BYTESWAP_FUNC: ValidationFunc<Self> =
        avb_hash_descriptor_validate_and_byteswap;
}

impl<'a> HashDescriptor<'a> {
    /// Extract a `HashDescriptor` from the given descriptor contents.
    ///
    /// # Arguments
    /// * `contents`: descriptor contents, including the header, in raw big-endian format.
    ///
    /// # Returns
    /// The new descriptor, or `DescriptorError` if the given `contents` aren't a valid
    /// `AvbHashDescriptor`.
    pub(super) fn new(contents: &'a [u8]) -> DescriptorResult<Self> {
        // Descriptor contains: header + name + salt + digest.
        let descriptor = parse_descriptor::<AvbHashDescriptor>(contents)?;
        let (partition_name, remainder) =
            split_slice(descriptor.body, descriptor.header.partition_name_len)?;
        let (salt, remainder) = split_slice(remainder, descriptor.header.salt_len)?;
        let (digest, _) = split_slice(remainder, descriptor.header.digest_len)?;

        // Extract the hash algorithm from the original raw header since the temporary
        // byte-swapped header doesn't live past this function.
        // The hash algorithm is a nul-terminated UTF-8 string which is identical in the raw
        // and byteswapped headers.
        let hash_algorithm = CStr::from_bytes_until_nul(&descriptor.raw_header.hash_algorithm)
            .map_err(|_| DescriptorError::InvalidValue)?
            .to_str()
            .map_err(|_| DescriptorError::InvalidUtf8)?;

        Ok(Self {
            image_size: descriptor.header.image_size,
            hash_algorithm,
            flags: HashDescriptorFlags(descriptor.header.flags),
            partition_name: from_utf8(partition_name).map_err(|_| DescriptorError::InvalidUtf8)?,
            salt,
            digest,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::size_of;

    /// A valid hash descriptor in raw big-endian format.
    ///
    /// It's fairly complicated to generate a descriptor programmatically, but for the purposes
    /// of these tests we don't care about the specific values, so this is just hardcoded.
    /// Actually extracting data from a descriptor is checked in the integration tests.
    const TEST_HASH_DESCRIPTOR: &[u8] = &[
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xA0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x73, 0x68, 0x61, 0x32, 0x35, 0x36,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09,
        0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x74, 0x65, 0x73,
        0x74, 0x5F, 0x70, 0x61, 0x72, 0x74, 0x10, 0x00, 0x89, 0xE6, 0xFD, 0x31, 0x42, 0x91, 0x7B,
        0x8C, 0x34, 0xAC, 0x7D, 0x30, 0x89, 0x7A, 0x90, 0x7A, 0x71, 0xBD, 0x3B, 0xF5, 0xD9, 0xB3,
        0x9D, 0x00, 0xBF, 0x93, 0x8B, 0x41, 0xDC, 0xF3, 0xB8, 0x4F, 0x00,
    ];

    #[test]
    fn new_hash_descriptor_success() {
        let descriptor = HashDescriptor::new(TEST_HASH_DESCRIPTOR);
        assert!(descriptor.is_ok());
    }

    #[test]
    fn new_hash_descriptor_too_short_header_fails() {
        let bad_header_size = size_of::<AvbHashDescriptor>() - 1;
        assert_eq!(
            HashDescriptor::new(&TEST_HASH_DESCRIPTOR[..bad_header_size]).unwrap_err(),
            DescriptorError::InvalidHeader
        );
    }

    #[test]
    fn new_hash_descriptor_too_short_contents_fails() {
        // The last byte is padding, so we need to drop 2 bytes to trigger an error.
        let bad_contents_size = TEST_HASH_DESCRIPTOR.len() - 2;
        assert_eq!(
            HashDescriptor::new(&TEST_HASH_DESCRIPTOR[..bad_contents_size]).unwrap_err(),
            DescriptorError::InvalidSize
        );
    }
}
