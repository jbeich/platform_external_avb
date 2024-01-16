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

//! Chain partition descriptors.

use super::{
    util::{parse_descriptor, split_slice, ValidateAndByteswap, ValidationFunc},
    DescriptorError, DescriptorResult,
};
use avb_bindgen::{
    avb_chain_partition_descriptor_validate_and_byteswap, AvbChainPartitionDescriptor,
};
use core::str::from_utf8;

/// `AvbChainPartitionDescriptorFlags`; see libavb docs for details.
pub use avb_bindgen::AvbChainPartitionDescriptorFlags as ChainPartitionDescriptorFlags;

/// Wraps a chain partition descriptor stored in a vbmeta image.
#[derive(Debug, PartialEq, Eq)]
pub struct ChainPartitionDescriptor<'a> {
    /// Chained partition rollback index location.
    pub rollback_index_location: u32,

    /// Chained partition name.
    ///
    /// Most partition names in this library are passed as `&CStr`, but inside
    /// descriptors the partition names are not nul-terminated making them
    /// ineligible for use directly as `&CStr`. If `&CStr` is required, one
    /// option is to allocate a nul-terminated copy of this string via
    /// `CString::new()` which can then be converted to `&CStr`.
    pub partition_name: &'a str,

    /// Chained partition public key.
    pub public_key: &'a [u8],

    /// Flags.
    pub flags: ChainPartitionDescriptorFlags,
}

// SAFETY: `VALIDATE_AND_BYTESWAP_FUNC` is the correct libavb validator for this descriptor type.
unsafe impl ValidateAndByteswap for AvbChainPartitionDescriptor {
    const VALIDATE_AND_BYTESWAP_FUNC: ValidationFunc<Self> =
        avb_chain_partition_descriptor_validate_and_byteswap;
}

impl<'a> ChainPartitionDescriptor<'a> {
    /// Extract a `ChainPartitionDescriptor` from the given descriptor contents.
    ///
    /// # Arguments
    /// * `contents`: descriptor contents, including the header, in raw big-endian format.
    ///
    /// # Returns
    /// The new descriptor, or `DescriptorError` if the given `contents` aren't a valid
    /// `AvbChainPartitionDescriptor`.
    pub(super) fn new(contents: &'a [u8]) -> DescriptorResult<Self> {
        // Descriptor contains: header + partition name + public key.
        let descriptor = parse_descriptor::<AvbChainPartitionDescriptor>(contents)?;
        let (partition_name, remainder) =
            split_slice(descriptor.body, descriptor.header.partition_name_len)?;
        let (public_key, _) = split_slice(remainder, descriptor.header.public_key_len)?;

        Ok(Self {
            flags: ChainPartitionDescriptorFlags(descriptor.header.flags),
            partition_name: from_utf8(partition_name).map_err(|_| DescriptorError::InvalidUtf8)?,
            rollback_index_location: descriptor.header.rollback_index_location,
            public_key,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::size_of;

    /// A valid chain partition descriptor in raw big-endian format.
    const TEST_CHAIN_PARTITION_DESCRIPTOR: &[u8] = &[
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08,
        0x60, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x0B, 0x00, 0x00, 0x08, 0x08, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x74, 0x65, 0x73, 0x74, 0x5F, 0x70, 0x61, 0x72, 0x74, 0x5F, 0x32, 0x00, 0x00,
        0x20, 0x00, 0xEF, 0x81, 0x68, 0xF3, 0xD0, 0x3D, 0xD3, 0xF9, 0xD2, 0x12, 0xB2, 0x60, 0x87,
        0x9B, 0xBF, 0x7B, 0xC2, 0xC5, 0xF4, 0xBD, 0x57, 0xEA, 0x51, 0x60, 0xC9, 0xFF, 0x79, 0xAF,
        0x0D, 0x8A, 0x33, 0x94, 0x26, 0x9B, 0x0E, 0x19, 0xC6, 0x2E, 0x54, 0x84, 0xA4, 0x04, 0x1B,
        0x7F, 0x56, 0x7C, 0x4E, 0xCF, 0x8E, 0x33, 0x8A, 0x55, 0x44, 0x73, 0x89, 0x50, 0x92, 0xF4,
        0x59, 0xE6, 0xCD, 0x76, 0x63, 0xCF, 0x1A, 0x3B, 0x32, 0x59, 0x0C, 0xFA, 0xCD, 0x91, 0x3D,
        0xEA, 0x54, 0x19, 0x2F, 0x76, 0xAF, 0x08, 0x45, 0xEA, 0x61, 0x54, 0x11, 0xEB, 0xA5, 0x79,
        0xDF, 0x07, 0x4A, 0xFE, 0x88, 0x5A, 0x31, 0x24, 0x67, 0x1B, 0x21, 0x0C, 0x06, 0xBA, 0xA4,
        0x55, 0x56, 0xC5, 0xDE, 0x00, 0xAB, 0xFB, 0xF8, 0xAB, 0xC4, 0x3D, 0xD8, 0x2B, 0xE5, 0x68,
        0xC0, 0xED, 0x96, 0x2A, 0xCF, 0xFA, 0x1A, 0xB3, 0x1D, 0xA9, 0x30, 0x3C, 0x63, 0x90, 0x93,
        0x17, 0xF2, 0x5E, 0xA6, 0xDC, 0x2C, 0x4A, 0x0E, 0x4C, 0x32, 0x3A, 0xFA, 0x51, 0xA2, 0xB8,
        0xA8, 0x37, 0x2B, 0x7A, 0x3D, 0xE1, 0x92, 0x00, 0x55, 0x1A, 0xF4, 0x55, 0xDD, 0xC8, 0xF5,
        0xB2, 0x72, 0xBA, 0x06, 0xBF, 0x07, 0xB9, 0x87, 0x45, 0x9E, 0x91, 0x86, 0x4D, 0x2D, 0x1D,
        0xED, 0x42, 0x65, 0x1C, 0x58, 0x25, 0xB6, 0xB1, 0x87, 0x53, 0xF0, 0x81, 0x3B, 0xDD, 0xB7,
        0x86, 0x41, 0xE0, 0x25, 0xA5, 0x84, 0x8C, 0x2D, 0x20, 0x89, 0x21, 0xA3, 0x84, 0xA2, 0xAD,
        0x2F, 0x3A, 0xD5, 0x72, 0x90, 0xD5, 0xDB, 0x2F, 0xE5, 0x59, 0x03, 0xFD, 0x4F, 0xF4, 0xF8,
        0x76, 0x31, 0x00, 0x21, 0xA1, 0xEA, 0x43, 0xEF, 0x8F, 0x49, 0xD3, 0x92, 0x47, 0xAA, 0x6C,
        0x20, 0x64, 0x7A, 0x85, 0x58, 0x12, 0x8A, 0x0B, 0x7B, 0x1C, 0x29, 0xC4, 0xEE, 0x75, 0xBB,
        0xD7, 0x5F, 0xEB, 0x7D, 0x5E, 0x54, 0xAF, 0xD1, 0x22, 0x56, 0x90, 0x74, 0xE3, 0x49, 0x83,
        0x22, 0x62, 0x99, 0x73, 0x2F, 0x3F, 0xFD, 0x33, 0x27, 0x5F, 0x27, 0x4D, 0xD4, 0xA6, 0x13,
        0x55, 0xDF, 0xF7, 0xE1, 0xF7, 0x69, 0xCC, 0xCA, 0x52, 0xC3, 0x98, 0x9B, 0x94, 0x4A, 0xDB,
        0xC0, 0xE2, 0xD7, 0x55, 0x35, 0x26, 0x3B, 0x3B, 0x58, 0x9E, 0x99, 0x78, 0xD5, 0xF7, 0x87,
        0x4A, 0xFF, 0xE3, 0x3D, 0xEB, 0x07, 0xB2, 0xD3, 0xE5, 0x7E, 0x49, 0x48, 0x17, 0x6B, 0xE8,
        0x19, 0x91, 0x28, 0x85, 0xFF, 0x6C, 0x71, 0x0B, 0xDC, 0xB8, 0xCE, 0xF0, 0x10, 0x17, 0xC2,
        0xFD, 0xA4, 0xC0, 0xF4, 0xAD, 0xFD, 0xCC, 0xC9, 0xA4, 0x05, 0xB7, 0x2F, 0x49, 0x98, 0xCB,
        0xCA, 0x19, 0x9C, 0x49, 0x95, 0x8C, 0x3C, 0xF3, 0x99, 0xC8, 0x87, 0x25, 0xDF, 0x36, 0x39,
        0xDD, 0x08, 0x56, 0x40, 0x2F, 0xDA, 0x6E, 0x62, 0x1C, 0x05, 0xF2, 0x35, 0x4B, 0x8F, 0xAB,
        0xEE, 0x60, 0xB8, 0x8B, 0x62, 0x67, 0xFB, 0xEA, 0x04, 0xBE, 0xE1, 0x8D, 0x54, 0x6A, 0xF6,
        0x49, 0x8D, 0x99, 0xD1, 0x96, 0x71, 0x5C, 0x62, 0xF5, 0x1C, 0x8F, 0xF4, 0xF0, 0x3F, 0xF7,
        0xF9, 0x37, 0x2E, 0x9A, 0xB7, 0x27, 0xE1, 0x88, 0xCF, 0x2B, 0xF0, 0xCC, 0x16, 0x2D, 0x05,
        0xF9, 0xEF, 0xB5, 0xC7, 0x8D, 0x65, 0x8A, 0x9B, 0x9F, 0xF9, 0xCC, 0x7F, 0xDA, 0xA4, 0x4D,
        0x41, 0x7F, 0xE6, 0xD3, 0x64, 0x93, 0xAC, 0xB6, 0x1D, 0x33, 0xA7, 0xB4, 0x83, 0x7D, 0xCA,
        0xBE, 0x59, 0xC5, 0x76, 0x2D, 0x9B, 0xEF, 0x9D, 0xB2, 0xFC, 0xE2, 0x1A, 0x33, 0x0C, 0x43,
        0x68, 0x9B, 0xEE, 0x9C, 0xC8, 0x7A, 0x10, 0xC0, 0xD6, 0x28, 0xCD, 0x40, 0x1D, 0xB6, 0x3F,
        0x8A, 0x80, 0x28, 0x2B, 0xB7, 0x92, 0xDB, 0xA1, 0xDE, 0x24, 0xB1, 0x03, 0x96, 0x5A, 0x8E,
        0xE3, 0xE4, 0x96, 0x3F, 0x7E, 0xDC, 0xF2, 0x53, 0x2F, 0x48, 0x45, 0xB2, 0xD4, 0x68, 0x84,
        0xAD, 0x1D, 0x07, 0x72, 0xC3, 0xA3, 0xFD, 0x0C, 0x16, 0x18, 0xF1, 0x6C, 0x7A, 0x85, 0x6B,
        0xA0, 0xC8, 0x80, 0xDA, 0xC5, 0x10, 0xD0, 0x87, 0x3F, 0xB6, 0x05, 0x63, 0x09, 0x39, 0x57,
        0x83, 0xED, 0x76, 0x5E, 0x95, 0x27, 0xA2, 0xE2, 0x30, 0x78, 0x28, 0xBC, 0x29, 0xC2, 0xFF,
        0x69, 0xDD, 0xB3, 0x26, 0x48, 0xEE, 0xF6, 0x10, 0x61, 0x24, 0xB0, 0x50, 0xFF, 0x61, 0xA7,
        0x8A, 0xF2, 0x62, 0xDE, 0x51, 0x60, 0x17, 0x81, 0x9D, 0xFF, 0xF4, 0xD2, 0x27, 0xAA, 0xE0,
        0x5A, 0xE5, 0xC5, 0x7C, 0xC2, 0xAD, 0xFF, 0xDC, 0xF6, 0x4B, 0x3D, 0xF9, 0xA2, 0x11, 0x17,
        0xE3, 0x20, 0x34, 0x7E, 0x5A, 0xA5, 0x09, 0xE2, 0xC8, 0x9C, 0x51, 0x28, 0x7A, 0xF6, 0xF3,
        0xF9, 0x74, 0xFD, 0x69, 0x17, 0xC3, 0x7B, 0xAE, 0x4C, 0x67, 0xBF, 0x72, 0xC3, 0x74, 0xDF,
        0x3F, 0xD0, 0xAB, 0x57, 0xBE, 0x21, 0x7F, 0x54, 0x51, 0xCE, 0xF7, 0x83, 0xE3, 0x3A, 0x62,
        0xDC, 0x5F, 0xA1, 0x71, 0x8D, 0xA2, 0x25, 0x6B, 0x07, 0xEE, 0x04, 0x4E, 0x65, 0xE0, 0xA6,
        0xE9, 0xF0, 0x17, 0xE5, 0x3A, 0xDE, 0x71, 0xDD, 0xE1, 0x3B, 0x12, 0x4E, 0x7C, 0x0E, 0x0D,
        0xE2, 0xBB, 0xD2, 0x48, 0x2A, 0xBA, 0x07, 0x00, 0xAF, 0x79, 0xB4, 0xFC, 0x15, 0x8D, 0xB9,
        0x67, 0xF5, 0x45, 0xED, 0xC4, 0x2B, 0x1D, 0x80, 0xD2, 0x8A, 0x3E, 0x70, 0xEA, 0x5A, 0xA1,
        0x33, 0x35, 0xC7, 0x79, 0x41, 0x18, 0xF7, 0x41, 0x9A, 0xF4, 0x02, 0xB8, 0x5F, 0x36, 0x96,
        0xC0, 0x68, 0x1E, 0xCE, 0xAF, 0x91, 0xED, 0x9B, 0x34, 0xD1, 0x84, 0x8A, 0xA8, 0x5B, 0xFD,
        0xA9, 0x83, 0x4A, 0x75, 0x1E, 0xED, 0xCF, 0x77, 0x23, 0x8A, 0x35, 0x9F, 0xF6, 0xAF, 0xF7,
        0x47, 0x5B, 0xA1, 0xE8, 0x44, 0x0A, 0x4C, 0xC6, 0x4A, 0xA3, 0x84, 0x84, 0x0A, 0x52, 0x62,
        0x1B, 0x28, 0xCE, 0x06, 0xF9, 0x8F, 0x2B, 0x4F, 0x63, 0x30, 0x56, 0x53, 0x26, 0xFD, 0x34,
        0x84, 0x3C, 0x5A, 0x80, 0x33, 0xD9, 0x06, 0x5E, 0xD7, 0xA4, 0xB0, 0xC9, 0xE7, 0xF2, 0xE7,
        0xD6, 0xEA, 0x69, 0xBC, 0xB0, 0x8D, 0x59, 0x66, 0x35, 0xCD, 0xE2, 0x5F, 0x68, 0x49, 0x4C,
        0xCA, 0xAD, 0xFF, 0x3E, 0xA2, 0x99, 0x2E, 0x27, 0x45, 0xF6, 0xB5, 0x68, 0x03, 0x54, 0x88,
        0xC2, 0x4D, 0xA5, 0xA5, 0xD5, 0x2F, 0x3E, 0x8B, 0x5E, 0xDA, 0x81, 0x62, 0xC0, 0x26, 0x68,
        0x5E, 0x5C, 0x19, 0x27, 0x69, 0xDC, 0x8E, 0x65, 0xE0, 0x40, 0xDB, 0x3B, 0xEB, 0xFF, 0x2E,
        0x9C, 0x32, 0x40, 0xD2, 0xB8, 0xF8, 0x24, 0xFA, 0x9C, 0x73, 0x0E, 0x0C, 0xE4, 0x6C, 0x50,
        0xEE, 0x89, 0x1B, 0x82, 0x6D, 0xC5, 0xE2, 0xB9, 0xB3, 0xAE, 0x20, 0xAE, 0xBF, 0xC0, 0x5E,
        0x31, 0x20, 0xA4, 0xAF, 0x6A, 0xF2, 0xD2, 0x66, 0x37, 0x52, 0x1A, 0x68, 0x85, 0x7E, 0x30,
        0x08, 0xCA, 0xB4, 0x1B, 0x8C, 0x79, 0xB0, 0x45, 0x00, 0xCF, 0xD1, 0x55, 0x54, 0xF6, 0x4A,
        0x8F, 0x19, 0xD8, 0x06, 0x62, 0xC3, 0xCE, 0xB2, 0x40, 0x47, 0xEE, 0x3E, 0x1B, 0xB8, 0x19,
        0xB1, 0xCB, 0x74, 0xD5, 0x70, 0xC9, 0x62, 0x00, 0xDD, 0x25, 0x56, 0x08, 0x9C, 0x53, 0xF6,
        0xDB, 0xF7, 0x08, 0xAD, 0xEF, 0x15, 0xAC, 0x55, 0x98, 0xB4, 0x76, 0xE0, 0x38, 0x57, 0x4D,
        0xA9, 0x48, 0x95, 0xAB, 0x9F, 0x1D, 0x7B, 0xA3, 0xDD, 0x64, 0x6F, 0xC4, 0xFA, 0xE6, 0x96,
        0x98, 0x44, 0xE1, 0x4A, 0x54, 0x6B, 0x80, 0x48, 0xD3, 0xC6, 0xEA, 0x62, 0x39, 0x77, 0xE0,
        0x74, 0xA5, 0xBF, 0xDB, 0x48, 0xF5, 0xA8, 0x0B, 0x63, 0x3A, 0x5A, 0x85, 0xC2, 0xC6, 0x34,
        0xF7, 0x84, 0x39, 0xAE, 0xA5, 0x0B, 0x43, 0xAC, 0x0F, 0xC5, 0x1A, 0xF9, 0x11, 0x2E, 0x97,
        0xF2, 0x72, 0xE5, 0x44, 0x8C, 0xC3, 0x11, 0x0F, 0xCE, 0x7A, 0x40, 0x81, 0xEA, 0x06, 0x13,
        0xCB, 0xA5, 0x63, 0x7D, 0xE4, 0x59, 0x82, 0xFF, 0x71, 0x44, 0xD5, 0x7C, 0xB6, 0x40, 0x1E,
        0x51, 0x86, 0xD3, 0x97, 0x55, 0xAF, 0x27, 0x39, 0x47, 0xE5, 0x26, 0xD5, 0xBB, 0x5B, 0xD4,
        0x39, 0x05, 0x62, 0xCF, 0xB8, 0xF2, 0x80, 0x39, 0xC1, 0x4B, 0xE9, 0x49, 0x86, 0xFB, 0x4F,
        0x79, 0xA4, 0x9B, 0xB9, 0x7A, 0x30, 0xD2, 0xF2, 0x52, 0xA8, 0x56, 0x9E, 0x12, 0x19, 0x93,
        0xAF, 0x3C, 0x57, 0xA6, 0x0E, 0x98, 0xCB, 0x07, 0xDF, 0xED, 0xBD, 0xEF, 0xFC, 0x88, 0x7A,
        0xDA, 0x8D, 0x09, 0x8A, 0xC4, 0xDE, 0xEF, 0x25, 0xFE, 0xE3, 0xB3, 0x3C, 0xE9, 0x0B, 0xE9,
        0xD2, 0x7A, 0xE6, 0x66, 0x02, 0xDA, 0x89, 0xB4, 0xB9, 0x31, 0xA0, 0x8A, 0xE7, 0x76, 0xE7,
        0xEC, 0xAC, 0x8C, 0xCB, 0x30, 0xC0, 0x2B, 0x72, 0x20, 0x8B, 0x87, 0xF0, 0x5B, 0x03, 0xB9,
        0xCF, 0x83, 0xF6, 0x6E, 0x4B, 0xE8, 0x34, 0x4F, 0xD4, 0xC4, 0xDD, 0xD0, 0x81, 0x94, 0xAD,
        0x7A, 0x0A, 0x3A, 0x6D, 0x6E, 0xC2, 0x10, 0x58, 0xE6, 0xDE, 0x8B, 0xF9, 0xC8, 0x69, 0x1C,
        0xB7, 0x99, 0x47, 0x48, 0xE7, 0x19, 0x89, 0x38, 0x73, 0x40, 0xA5, 0xEC, 0xD3, 0xCD, 0x0F,
        0x50, 0x6B, 0x66, 0x86, 0x52, 0x26, 0x73, 0xE9, 0xD2, 0x77, 0x0C, 0xD1, 0x3D, 0xB1, 0x82,
        0x17, 0xCD, 0x26, 0x1F, 0x70, 0x6E, 0xFC, 0xC0, 0xF4, 0xB3, 0x84, 0x29, 0x82, 0xE4, 0xC8,
        0xD3, 0x33, 0xB3, 0xE0, 0xAE, 0x93, 0x48, 0xB9, 0x1E, 0x15, 0x84, 0x3E, 0x17, 0x37, 0x14,
        0x26, 0xB8, 0x29, 0x49, 0x64, 0xF2, 0xE7, 0x4C, 0xD1, 0xC2, 0xE0, 0x8A, 0x57, 0x5B, 0x66,
        0xA7, 0x94, 0x94, 0xD9, 0x8F, 0x1D, 0xB4, 0x80, 0xED, 0xC7, 0x41, 0xF6, 0x89, 0xA3, 0x67,
        0x89, 0x85, 0xC3, 0x79, 0x60, 0x9B, 0xAC, 0x92, 0xB0, 0xC1, 0x92, 0xDF, 0xE5, 0xEA, 0x44,
        0xFC, 0x28, 0x4C, 0xF6, 0x72, 0x97, 0x22, 0x08, 0x88, 0x21, 0x0D, 0x9E, 0xBD, 0x2D, 0x10,
        0x0F, 0xFC, 0x8B, 0xCB, 0x13, 0x63, 0x6A, 0xAD, 0x62, 0x63, 0xB2, 0xA7, 0x35, 0xE3, 0xD0,
        0x06, 0xF3, 0x09, 0x10, 0x0D, 0xC3, 0x91, 0x29, 0x7C, 0xE7, 0x25, 0x3E, 0x6D, 0xF1, 0x88,
        0x5E, 0xEF, 0xEE, 0x0E, 0x70, 0x35, 0xEF, 0x31, 0x80, 0x53, 0xD7, 0x17, 0x7C, 0xD4, 0xAC,
        0xC5, 0xEC, 0x92, 0x03, 0x1A, 0x1F, 0xD6, 0x6D, 0xEF, 0x34, 0x04, 0xC4, 0xAD, 0xFF, 0xF0,
        0xF1, 0x21, 0x94, 0xA0, 0x93, 0xFA, 0xD5, 0x09, 0xA0, 0xA6, 0xC7, 0x42, 0x20, 0x11, 0xD0,
        0xB0, 0xC4, 0x0A, 0x6D, 0xA8, 0x60, 0x1F, 0xC7, 0x1E, 0x48, 0xAD, 0x25, 0x44, 0xEB, 0xC6,
        0x52, 0x49, 0x9E, 0xD5, 0x91, 0xE6, 0xEB, 0x89, 0xB0, 0x74, 0xFC, 0xA8, 0xA9, 0x20, 0xB8,
        0xBB, 0xB5, 0x68, 0xAB, 0xFC, 0xC0, 0xAF, 0x73, 0xFA, 0x4F, 0x32, 0x56, 0xCB, 0x30, 0x60,
        0x9C, 0xDB, 0xD1, 0x13, 0x07, 0xDB, 0x75, 0x1D, 0x08, 0x35, 0xE0, 0x9C, 0xFA, 0x1C, 0x74,
        0x7A, 0x58, 0xED, 0x29, 0x19, 0xD4, 0xBD, 0x6A, 0x9A, 0x8E, 0xB2, 0xC1, 0xFB, 0x92, 0xE0,
        0x03, 0xBB, 0x09, 0x0D, 0xE1, 0x73, 0xDC, 0x70, 0x4B, 0x38, 0x7F, 0x41, 0xB7, 0x28, 0x5F,
        0x95, 0x29, 0x4D, 0x1C, 0xE7, 0x56, 0xB2, 0x69, 0xE9, 0xE3, 0x81, 0x4C, 0xCB, 0x3F, 0x80,
        0xEF, 0xE0, 0xD7, 0xEA, 0xC6, 0xD0, 0xCF, 0xE2, 0xCC, 0x51, 0x52, 0x4A, 0xA4, 0xC9, 0x84,
        0x47, 0x6D, 0x74, 0xFD, 0x34, 0xF3, 0xE4, 0xFF, 0x12, 0x6C, 0xF0, 0x15, 0x23, 0xA1, 0xDE,
        0xDA, 0x0E, 0x5A, 0x07, 0x72, 0xF0, 0xE6, 0x1B, 0xED, 0x8D, 0xC3, 0x61, 0x5D, 0x54, 0x7D,
        0x81, 0x13, 0xD2, 0x3D, 0x8F, 0x0B, 0xFC, 0x00, 0x97, 0xAE, 0x88, 0x25, 0x8E, 0x64, 0x78,
        0xCE, 0xE3, 0x89, 0xFB, 0xB6, 0xBF, 0x4E, 0xA6, 0x8D, 0x08, 0x3A, 0x93, 0x8D, 0x7F, 0x78,
        0x1C, 0xE3, 0x70, 0xC0, 0x3C, 0xBD, 0x10, 0xA0, 0x53, 0xE7, 0xD6, 0xA3, 0x75, 0x26, 0xF6,
        0x10, 0x22, 0x0E, 0xB6, 0x84, 0x80, 0x5E, 0x62, 0x20, 0x4F, 0x21, 0x0A, 0x79, 0x0E, 0x70,
        0x09, 0xCF, 0x71, 0xFB, 0x03, 0x68, 0x51, 0xF5, 0xFC, 0xDB, 0x86, 0xBF, 0x64, 0x0C, 0x94,
        0xE0, 0xC0, 0xA4, 0x12, 0xA6, 0x6A, 0xBF, 0x5A, 0x7F, 0x20, 0x5D, 0x51, 0x5B, 0x6C, 0x85,
        0xD6, 0x5B, 0x7D, 0xA2, 0xF7, 0xE4, 0x0D, 0xCF, 0x3D, 0x05, 0x67, 0xD2, 0xD8, 0x51, 0xF0,
        0x29, 0x42, 0xA0, 0xF9, 0xA6, 0x7E, 0x7F, 0x9F, 0x44, 0x27, 0x46, 0x0D, 0xE2, 0x97, 0xD1,
        0x72, 0x19, 0xB9, 0x40, 0xDD, 0xCF, 0xAF, 0x83, 0x10, 0xD6, 0xE9, 0x06, 0x83, 0x1B, 0xE3,
        0x9C, 0x2C, 0xF1, 0xD5, 0x27, 0xF2, 0xFF, 0xAB, 0xD9, 0x5D, 0xFE, 0x14, 0x5C, 0x8F, 0x0A,
        0xDE, 0xCF, 0xC4, 0xB1, 0x67, 0xF3, 0x8A, 0xE0, 0x3F, 0xD8, 0xD2, 0xFE, 0x4D, 0x42, 0xBD,
        0x8F, 0x2A, 0xE2, 0x0F, 0x59, 0xA3, 0x68, 0x81, 0x53, 0xA8, 0xB2, 0xC7, 0x5A, 0xD3, 0x60,
        0xBD, 0x9A, 0x90, 0x0D, 0x81, 0x0D, 0x5C, 0xE1, 0x7A, 0x5B, 0xE3, 0x54, 0x36, 0xCD, 0x15,
        0xD6, 0xB2, 0xB8, 0x81, 0xB5, 0x6F, 0xD9, 0x72, 0x77, 0xE4, 0xB2, 0xCD, 0x82, 0xF2, 0x5D,
        0xF3, 0x52, 0x86, 0xEC, 0x72, 0x4A, 0x12, 0x52, 0x80, 0xA0, 0x36, 0xBC, 0xB6, 0x02, 0xBD,
        0x00, 0x38, 0xC5, 0xEA, 0x30, 0x26, 0x54, 0x74, 0x62, 0xA0, 0x6E, 0x4A, 0x45, 0x72, 0x9C,
        0xA0, 0x78, 0x4E, 0x31, 0xD1, 0x10, 0x3B, 0x7F, 0x99, 0x1E, 0xAA, 0x89, 0xD7, 0x12, 0x1C,
        0xFD, 0x67, 0x51, 0x0F, 0xB1, 0x8D, 0x4D, 0x5B, 0x03, 0x06, 0x88, 0x84, 0xC5, 0x92, 0xD6,
        0xBA, 0xD5, 0x68, 0x15, 0xD4, 0xEB, 0x4C, 0xFF, 0xAB, 0x1F, 0xEB, 0x7E, 0xA2, 0x7D, 0xD4,
        0xE2, 0x8C, 0x62, 0xDB, 0x6D, 0x18, 0xF8, 0xD8, 0x38, 0xB4, 0x85, 0x53, 0xCD, 0x73, 0x76,
        0x11, 0x65, 0x74, 0x63, 0x34, 0x9F, 0x70, 0xCD, 0xC2, 0x60, 0xAB, 0x0A, 0xD9, 0xBF, 0x16,
        0x36, 0x58, 0xEA, 0xCC, 0x78, 0x98, 0x2A, 0x27, 0x4F, 0x85, 0xAA, 0xDB, 0x0B, 0xEC, 0xF9,
        0x25, 0x88, 0xEC, 0xD5, 0x3F, 0xC5, 0xE2, 0x29, 0xBB, 0x1F, 0xE8, 0x70, 0xA5, 0xF1, 0x8C,
        0x5C, 0x66, 0xBD, 0x15, 0x4D, 0x05, 0x2B, 0x2E, 0x26, 0x63, 0x00, 0x4C, 0x0D, 0x6B, 0xEA,
        0xCF, 0xCB, 0x55, 0x09, 0x4F, 0xFB, 0x18, 0x98, 0xB7, 0xDB, 0xE3, 0xC9, 0x65, 0x38, 0x15,
        0xDA, 0x4C, 0x11, 0xD5, 0x3A, 0xC0, 0x18, 0xB9, 0x8F, 0xBB, 0x36, 0xFA, 0x61, 0x19, 0x7D,
        0xE1, 0x52, 0x58, 0xDC, 0x46, 0x14, 0x80, 0x7C, 0x83, 0xC0, 0x2F, 0x15, 0x42, 0x05, 0x27,
        0x50, 0x8E, 0x63, 0xF8, 0x32, 0x7B, 0x4C, 0x98, 0x62, 0x29, 0x18, 0x10, 0xFF, 0x45, 0x3B,
        0x9B, 0xAD, 0xB3, 0xD7, 0x62, 0x0D, 0x8C, 0x1A, 0xAB, 0x8B, 0x5D, 0x50, 0xD6, 0xAF, 0x59,
        0xFC, 0x18, 0x11, 0x61, 0xA5, 0xB1, 0x03, 0x90, 0x90, 0x06, 0x2F, 0x0C, 0x89, 0x95, 0x82,
        0x2B, 0xE2, 0xDF, 0x15, 0x84, 0x47, 0x25, 0x3B, 0x8A, 0xBF, 0x91, 0x32, 0x25, 0xC1, 0xBD,
        0xEF, 0x3E, 0x9A, 0x54, 0xA0, 0x58, 0x9C, 0x1F, 0x69, 0x58, 0x0E, 0x25, 0x65, 0xB2, 0x8C,
        0x75, 0xE9, 0xC4, 0xC8, 0xD7, 0x38, 0x50, 0x4E, 0xE8, 0xE0, 0x8D, 0xE4, 0x14, 0xC6, 0x4D,
        0x8C, 0xEE, 0x48, 0x64, 0xEC, 0xF9, 0xA6, 0x09, 0x48, 0x51, 0x5C, 0xC0, 0x76, 0x80, 0x00,
    ];

    #[test]
    fn new_chain_partition_descriptor_success() {
        let descriptor = ChainPartitionDescriptor::new(TEST_CHAIN_PARTITION_DESCRIPTOR);
        assert!(descriptor.is_ok());
    }

    #[test]
    fn new_chain_partition_descriptor_too_short_header_fails() {
        let bad_header_size = size_of::<AvbChainPartitionDescriptor>() - 1;
        assert_eq!(
            ChainPartitionDescriptor::new(&TEST_CHAIN_PARTITION_DESCRIPTOR[..bad_header_size])
                .unwrap_err(),
            DescriptorError::InvalidHeader
        );
    }

    #[test]
    fn new_chain_partition_descriptor_too_short_contents_fails() {
        // The last byte is padding, so we need to drop 2 bytes to trigger an error.
        let bad_contents_size = TEST_CHAIN_PARTITION_DESCRIPTOR.len() - 2;
        assert_eq!(
            ChainPartitionDescriptor::new(&TEST_CHAIN_PARTITION_DESCRIPTOR[..bad_contents_size])
                .unwrap_err(),
            DescriptorError::InvalidSize
        );
    }
}
