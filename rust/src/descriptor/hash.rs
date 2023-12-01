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

use super::util::extract_slice;
use avb_bindgen::{avb_hash_descriptor_validate_and_byteswap, AvbHashDescriptor};
use core::{
    ffi::CStr,
    mem::{size_of, MaybeUninit},
    str::from_utf8,
};

/// `AvbHashDescriptorFlags`; see libavb docs for details.
pub use avb_bindgen::AvbHashDescriptorFlags as HashDescriptorFlags;

/// Wraps a Hash descriptor stored in a vbmeta image.
#[derive(Debug)]
pub struct HashDescriptor<'a> {
    /// Hash descriptor header.
    ///
    /// The raw data is kept private to avoid confusion by exposing C details e.g. `salt_len`.
    /// Any useful data should be exposed explicitly.
    header: AvbHashDescriptor,

    /// Partition name.
    pub partition_name: &'a str,

    /// Salt used to hash the image.
    pub salt: &'a [u8],

    /// Image hash digest.
    pub digest: &'a [u8],
}

impl<'a> HashDescriptor<'a> {
    /// Extract a `HashDescriptor` from the given descriptor contents.
    ///
    /// # Arguments
    /// * `contents`: descriptor contents, including the header, in raw big-endian format.
    ///
    /// # Returns
    /// The new descriptor, or `None` if the given `contents` aren't a valid `AvbHashDescriptor`.
    pub(super) fn new(contents: &'a [u8]) -> Option<Self> {
        // Check that we can interpret `contents` as an `AvbHashDescriptor`. We don't need to check
        // alignment because `AvbHashDescriptor` is `repr(packed)` so the compiler will properly
        // support unaligned loads/stores.
        if contents.len() < size_of::<AvbHashDescriptor>() {
            return None;
        }

        let header = {
            let mut header = MaybeUninit::uninit();
            // SAFETY:
            // * we ensured that `contents` can be cast to an `AvbHashDescriptor` pointer
            // * `avb_hash_descriptor_validate_and_byteswap()` checks the validity of the fields
            //   and initializes `header` on success
            // * even if `contents` are corrupted somehow, this will only give bogus header values
            //   as output which will be caught below; it will never try to access memory outside
            //   of `contents`.
            unsafe {
                if !avb_hash_descriptor_validate_and_byteswap(
                    contents.as_ptr() as *const AvbHashDescriptor,
                    header.as_mut_ptr(),
                ) {
                    return None;
                }
                header.assume_init()
            }
        };

        // Descriptor contains: header + name + salt + digest.
        let (_, contents) = extract_slice(contents, size_of::<AvbHashDescriptor>())?;
        let (partition_name, contents) = extract_slice(contents, header.partition_name_len)?;
        let (salt, contents) = extract_slice(contents, header.salt_len)?;
        let (digest, _) = extract_slice(contents, header.digest_len)?;

        Some(Self {
            header,
            partition_name: from_utf8(partition_name).ok()?,
            salt,
            digest,
        })
    }

    /// Returns the size of the image.
    pub fn image_size(&self) -> u64 {
        self.header.image_size
    }

    /// Returns the hash algorithm name e.g. `sha256`/`sha512`, or `None` on invalid data.
    pub fn hash_algorithm(&self) -> Option<&str> {
        let cstr = CStr::from_bytes_until_nul(&self.header.hash_algorithm).ok()?;
        cstr.to_str().ok()
    }

    /// Returns the flags for this descriptor.
    pub fn flags(&self) -> HashDescriptorFlags {
        HashDescriptorFlags(self.header.flags)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::align_of;

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
        assert!(HashDescriptor::new(TEST_HASH_DESCRIPTOR).is_some());
    }

    #[test]
    fn new_hash_descriptor_too_short_header_fails() {
        let bad_header_size = size_of::<AvbHashDescriptor>() - 1;
        assert!(HashDescriptor::new(&TEST_HASH_DESCRIPTOR[..bad_header_size]).is_none());
    }

    #[test]
    fn new_hash_descriptor_too_short_contents_fails() {
        // The last byte is padding, so we need to drop 2 bytes to trigger an error.
        let bad_contents_size = TEST_HASH_DESCRIPTOR.len() - 2;
        assert!(HashDescriptor::new(&TEST_HASH_DESCRIPTOR[..bad_contents_size]).is_none());
    }

    #[test]
    fn hash_descriptor_is_packed() {
        // If this test fails then we need to check for proper alignment in `HashDescriptor::new()`
        // before we can cast a `&[u8]` to `*AvbHashDescriptor`.
        assert_eq!(align_of::<AvbHashDescriptor>(), 1);
    }
}
