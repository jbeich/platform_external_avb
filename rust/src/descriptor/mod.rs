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

//! Descriptor extraction and handling.
//!
//! Descriptors are information encoded into vbmeta images which can be
//! extracted from the resulting data after performing verification.

extern crate alloc;

use crate::VbmetaData;
use alloc::vec::Vec;
use avb_bindgen::{
    avb_descriptor_foreach, avb_descriptor_validate_and_byteswap, AvbDescriptor, AvbDescriptorTag,
};
use core::{ffi::c_void, mem::size_of, slice::from_raw_parts};

/// A single descriptor.
// TODO(b/290110273): add support for full descriptor contents.
#[derive(Debug)]
pub enum Descriptor<'a> {
    /// Wraps `AvbPropertyDescriptor`.
    Property(&'a [u8]),
    /// Wraps `AvbHashtreeDescriptor`.
    Hashtree(&'a [u8]),
    /// Wraps `AvbHashDescriptor`.
    Hash(&'a [u8]),
    /// Wraps `AvbKernelCmdlineDescriptor`.
    KernelCommandline(&'a [u8]),
    /// Wraps `AvbChainPartitionDescriptor`.
    ChainPartition(&'a [u8]),
}

impl<'a> Descriptor<'a> {
    /// Extracts the fully-typed descriptor from the generic `AvbDescriptor` header.
    ///
    /// # Arguments
    /// * `raw_descriptor`: the raw `AvbDescriptor` pointing into the vbmeta image.
    ///
    /// # Returns
    /// The fully-typed `Descriptor`, or `None` if parsing the descriptor failed.
    ///
    /// # Safety
    /// `raw_descriptor` must point to a valid `AvbDescriptor`, including the `num_bytes_following`
    /// data contents, that lives at least as long as `'a`.
    unsafe fn new(raw_descriptor: *const AvbDescriptor) -> Option<Self> {
        // Transform header to host-endian.
        let mut descriptor = AvbDescriptor {
            tag: 0,
            num_bytes_following: 0,
        };
        // SAFETY: both args point to valid `AvbDescriptor` objects.
        if !unsafe { avb_descriptor_validate_and_byteswap(raw_descriptor, &mut descriptor) } {
            return None;
        }

        // Extract the descriptor header and contents bytes. The descriptor sub-type headers
        // include the top-level header as the first member, so we need to grab the entire
        // descriptor including the top-level header.
        //
        // SAFETY: `raw_descriptor` points to the header plus `num_bytes_following` bytes.
        let contents = unsafe {
            from_raw_parts(
                raw_descriptor as *const u8,
                size_of::<AvbDescriptor>()
                    .checked_add(descriptor.num_bytes_following.try_into().ok()?)?,
            )
        };

        match descriptor.tag.try_into().ok()? {
            AvbDescriptorTag::AVB_DESCRIPTOR_TAG_PROPERTY => Some(Descriptor::Property(contents)),
            AvbDescriptorTag::AVB_DESCRIPTOR_TAG_HASHTREE => Some(Descriptor::Hashtree(contents)),
            AvbDescriptorTag::AVB_DESCRIPTOR_TAG_HASH => Some(Descriptor::Hash(contents)),
            AvbDescriptorTag::AVB_DESCRIPTOR_TAG_KERNEL_CMDLINE => {
                Some(Descriptor::KernelCommandline(contents))
            }
            AvbDescriptorTag::AVB_DESCRIPTOR_TAG_CHAIN_PARTITION => {
                Some(Descriptor::ChainPartition(contents))
            }
            _ => None,
        }
    }
}

/// Returns a vector of descriptors extracted from the given vbmeta image.
///
/// # Arguments
/// * `vbmeta`: the `VbmetaData` object to extract descriptors from.
///
/// # Returns
/// The descriptors, or `None` if any error occurred.
///
/// # Safety
/// `vbmeta` must have been validated by `slot_verify()`.
pub(crate) unsafe fn get_descriptors(vbmeta: &VbmetaData) -> Option<Vec<Descriptor>> {
    let mut descriptors = Vec::<Descriptor>::default();

    // Use `avb_descriptor_foreach()` to grab all the descriptor pointers in `vmbeta.data()`.
    // This implementation processes all the descriptors immediately, so that any error is
    // detected here and working with descriptors can be error-free.
    //
    // SAFETY:
    // * the caller ensures that `vbmeta` has been validated by `slot_verify()`, which satisfies
    //   the libavb `avb_vbmeta_image_verify()` requirement.
    // * `avb_descriptor_foreach()` ensures the validity of each descriptor pointer passed to
    //   the `fill_descriptors_vec()` callback.
    // * our lifetimes guarantee that the raw descriptor data in `vbmeta` will remain unchanged for
    //   the lifetime of the returned `Descriptor` objects.
    // * the `user_data` param is a valid `Vec<Descriptor>` with no other concurrent access.
    if !unsafe {
        avb_descriptor_foreach(
            vbmeta.data().as_ptr(),
            vbmeta.data().len(),
            Some(fill_descriptors_vec),
            &mut descriptors as *mut _ as *mut c_void,
        )
    } {
        // If we stopped iteration early, something went wrong.
        return None;
    }

    Some(descriptors)
}

/// Adds the given descriptor to the `Vec` pointed to by `user_data`.
///
/// Serves as a C callback for use with `avb_descriptor_foreach()`.
///
/// # Returns
/// True on success, false on failure (which will stop iteration early).
///
/// # Safety
/// * `descriptor` must point to a valid `AvbDescriptor`, including the `num_bytes_following`
///   data contents, which remains valid and unmodified for the lifetime of the `Descriptor` objects
///   in `user_data`.
/// * `user_data` must point to a valid `Vec<Descriptor>` with no other concurrent access.
unsafe extern "C" fn fill_descriptors_vec(
    descriptor: *const AvbDescriptor,
    user_data: *mut c_void,
) -> bool {
    // SAFETY: caller ensures that `descriptor` points to a valid `AvbDescriptor` with header and
    // body contents, which remains unmodified at least as long as the new `Descriptor`.
    if let Some(d) = unsafe { Descriptor::new(descriptor) } {
        // SAFETY: `user_data` gives exclusive access to a valid `Vec<Descriptor>`.
        let descriptors = unsafe { (user_data as *mut Vec<Descriptor>).as_mut() };
        // We never pass a NULL `user_data` into this callback so we know `unwrap()` will succeed.
        descriptors.unwrap().push(d);
        true
    } else {
        // Stop iteration early, which will be detected by `get_descriptors()` and return failure.
        false
    }
}
