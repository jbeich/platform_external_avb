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
    DescriptorError, DescriptorResult,
    util::{ValidateAndByteswap, ValidationFunc, parse_descriptor, split_slice},
};
use avb_bindgen::{AvbPropertyDescriptor, avb_property_descriptor_validate_and_byteswap};
use core::ffi::CStr;

/// Wraps an `AvbPropertyDescriptor` stored in a vbmeta image.
#[derive(Debug, PartialEq, Eq)]
pub struct PropertyDescriptor<'a> {
    /// Key is always UTF-8.
    pub key: &'a str,
    /// The same content as key, but nul terminated.
    pub key_cstr: &'a CStr,

    /// Value can be arbitrary bytes.
    pub value_with_nul: &'a [u8],
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
        // Guaranteed to be nul terminated by libavb.
        let (key_bytes_with_nul, remainder) =
            split_slice(descriptor.body, descriptor.header.key_num_bytes + 1)?;
        // Note: UTF-8 keys containing null bytes will fail here, but such keys are unlikely
        // from command line input.
        let key_cstr = CStr::from_bytes_with_nul(key_bytes_with_nul)?;
        let key = key_cstr.to_str()?;

        // Guaranteed to be nul terminated by libavb.
        let (value_with_nul, _) = split_slice(remainder, descriptor.header.value_num_bytes + 1)?;
        if !value_with_nul.ends_with(&[0]) {
            return Err(DescriptorError::InvalidContents);
        }

        Ok(Self {
            key,
            key_cstr,
            value_with_nul,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::{fs, mem::size_of};

    /// A valid descriptor that we've pre-generated as test data.
    fn test_contents() -> Vec<u8> {
        fs::read("testdata/property_descriptor.bin").unwrap()
    }

    #[test]
    fn new_property_descriptor_success() {
        assert!(PropertyDescriptor::new(&test_contents()).is_ok());
    }

    #[test]
    fn new_property_descriptor_too_short_header_fails() {
        let bad_header_size = size_of::<AvbPropertyDescriptor>() - 1;
        assert_eq!(
            PropertyDescriptor::new(&test_contents()[..bad_header_size]).unwrap_err(),
            DescriptorError::InvalidHeader
        );
    }

    #[test]
    fn new_property_descriptor_too_short_contents_fails() {
        // The last 2 bytes are padding, so we need to drop 3 bytes to trigger an error.
        let bad_contents_size = test_contents().len() - 3;
        assert_eq!(
            PropertyDescriptor::new(&test_contents()[..bad_contents_size]).unwrap_err(),
            DescriptorError::InvalidSize
        );
    }
}
