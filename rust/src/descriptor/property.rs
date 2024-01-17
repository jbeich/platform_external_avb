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

//! Property descriptors.

use super::{
    util::{parse_descriptor, split_slice, ValidateAndByteswap, ValidationFunc},
    DescriptorError, DescriptorResult,
};
use avb_bindgen::{avb_property_descriptor_validate_and_byteswap, AvbPropertyDescriptor};
use core::str::from_utf8;

/// Checks that the first byte is nul and discards it.
/// Returns the remainder of `bytes` on success, or `DescriptorError` if the byte wasn't nul.
fn extract_nul(bytes: &[u8]) -> DescriptorResult<&[u8]> {
    let (nul, remainder) = split_slice(bytes, 1)?;
    match nul {
        b"\0" => Ok(remainder),
        _ => Err(DescriptorError::InvalidContents),
    }
}

/// Wraps an `AvbPropertyDescriptor` stored in a vbmeta image.
#[derive(Debug, PartialEq, Eq)]
pub struct PropertyDescriptor<'a> {
    /// Key is always UTF-8.
    pub key: &'a str,

    /// Value can be arbitrary bytes.
    pub value: &'a [u8],
}

// SAFETY: `VALIDATE_AND_BYTESWAP_FUNC` is the correct libavb validator for this descriptor type.
unsafe impl ValidateAndByteswap for AvbPropertyDescriptor {
    const VALIDATE_AND_BYTESWAP_FUNC: ValidationFunc<Self> =
        avb_property_descriptor_validate_and_byteswap;
}

impl<'a> PropertyDescriptor<'a> {
    /// Extract a `PropertyDescriptor` from the given descriptor contents.
    ///
    /// # Arguments
    /// * `contents`: descriptor contents, including the header, in raw big-endian format.
    ///
    /// # Returns
    /// The new descriptor, or `DescriptorError` if the given `contents` aren't a valid
    /// `AvbPropertyDescriptor`.
    pub(super) fn new(contents: &'a [u8]) -> DescriptorResult<Self> {
        // Descriptor contains: header + key + nul + value + nul.
        let descriptor = parse_descriptor::<AvbPropertyDescriptor>(contents)?;
        let (key, remainder) = split_slice(descriptor.body, descriptor.header.key_num_bytes)?;
        let remainder = extract_nul(remainder)?;
        let (value, remainder) = split_slice(remainder, descriptor.header.value_num_bytes)?;
        extract_nul(remainder)?;

        Ok(Self {
            key: from_utf8(key).map_err(|_| DescriptorError::InvalidUtf8)?,
            value,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::size_of;

    /// A valid property descriptor in raw big-endian format.
    const TEST_PROPERTY_DESCRIPTOR: &[u8] = &[
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0D, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x0F, 0x74, 0x65, 0x73, 0x74, 0x5F, 0x70, 0x72, 0x6F, 0x70, 0x5F, 0x6B, 0x65, 0x79,
        0x00, 0x74, 0x65, 0x73, 0x74, 0x5F, 0x70, 0x72, 0x6F, 0x70, 0x5F, 0x76, 0x61, 0x6C, 0x75,
        0x65, 0x00, 0x00, 0x00,
    ];

    #[test]
    fn new_property_descriptor_success() {
        let descriptor = PropertyDescriptor::new(TEST_PROPERTY_DESCRIPTOR);
        assert!(descriptor.is_ok());
    }

    #[test]
    fn new_property_descriptor_too_short_header_fails() {
        let bad_header_size = size_of::<AvbPropertyDescriptor>() - 1;
        assert_eq!(
            PropertyDescriptor::new(&TEST_PROPERTY_DESCRIPTOR[..bad_header_size]).unwrap_err(),
            DescriptorError::InvalidHeader
        );
    }

    #[test]
    fn new_property_descriptor_too_short_contents_fails() {
        // The last 2 bytes are padding, so we need to drop 3 bytes to trigger an error.
        let bad_contents_size = TEST_PROPERTY_DESCRIPTOR.len() - 3;
        assert_eq!(
            PropertyDescriptor::new(&TEST_PROPERTY_DESCRIPTOR[..bad_contents_size]).unwrap_err(),
            DescriptorError::InvalidSize
        );
    }
}
