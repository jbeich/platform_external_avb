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
    /// # Safety
    /// `contents` must point to a valid `AvbHashDescriptor`.
    pub(super) unsafe fn new(contents: &'a [u8]) -> Option<Self> {
        let header = {
            let mut header = MaybeUninit::uninit();
            // SAFETY:
            // * `contents` points to a valid `AvbHashDescriptor` object
            // * `avb_hash_descriptor_validate_and_byteswap()` initializes `header`
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
