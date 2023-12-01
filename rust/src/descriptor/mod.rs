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

mod hash;
mod util;

use crate::VbmetaData;
use alloc::vec::Vec;
use avb_bindgen::{
    avb_descriptor_foreach, avb_descriptor_validate_and_byteswap, AvbDescriptor, AvbDescriptorTag,
};
use core::{ffi::c_void, mem::size_of, slice::from_raw_parts};

pub use hash::{HashDescriptor, HashDescriptorFlags};

/// A single descriptor.
// TODO(b/290110273): add support for full descriptor contents.
#[derive(Debug)]
pub enum Descriptor<'a> {
    /// Wraps `AvbPropertyDescriptor`.
    Property,
    /// Wraps `AvbHashtreeDescriptor`.
    Hashtree,
    /// Wraps `AvbHashDescriptor`.
    Hash(HashDescriptor<'a>),
    /// Wraps `AvbKernelCmdlineDescriptor`.
    KernelCommandline,
    /// Wraps `AvbChainPartitionDescriptor`.
    ChainPartition,
    /// Unknown or invalid descriptor format.
    ///
    /// This indicates an internal error when parsing the descriptor. It's OK to continue to
    /// iterate after encountering this, any following descriptors may still be retrievable.
    Unknown,
}

/// Iterator for accessing all the descriptors in a vbmeta image.
///
/// Creating a descriptor iterator allocates a small amount of heap memory (1 pointer per
/// descriptor).
pub struct DescriptorIterator<'a> {
    /// The vbmeta image we're iterating over; hold a borrow since we're going to have pointers
    /// pointing into this data.
    _vbmeta: &'a VbmetaData,
    /// Pointers to each descriptor in `_vbmeta`.
    descriptor_ptrs: Vec<*const AvbDescriptor>,
    /// Next item to pull from `descriptor_ptrs`.
    index: usize,
}

impl<'a> DescriptorIterator<'a> {
    /// Creates a new iterator over the descriptors in the given vbmeta image, or `None` on error.
    ///
    /// # Safety
    /// `vbmeta` must have been validated by `slot_verify()`.
    pub(crate) unsafe fn new(vbmeta: &'a VbmetaData) -> Option<Self> {
        let mut descriptor_ptrs = Vec::<*const AvbDescriptor>::default();

        // Use `avb_descriptor_foreach()` to grab all the descriptor pointers in `vmbeta.data()`.
        // We will process these into full `Descriptor` objects during iteration so that we only
        // have to allocate a single pointer per descriptor here.
        //
        // SAFETY:
        // * the caller ensures that `vbmeta` has been validated by `slot_verify()`, which satisfies
        //   the libavb `avb_vbmeta_image_verify()` requirement.
        // * we retain a borrow of `vbmeta` below so it cannot be modified while we exist, which
        //   ensures the resulting pointers will remain valid for at least `'a`.
        // * the `user_data` param is a valid `Vec<*const AvbDescriptor>` with no other concurrent
        //   access as required by `fill_descriptor_ptrs_vec()`
        unsafe {
            avb_descriptor_foreach(
                vbmeta.data().as_ptr(),
                vbmeta.data().len(),
                Some(fill_descriptor_ptrs_vec),
                &mut descriptor_ptrs as *mut _ as *mut c_void,
            )
        };

        Some(Self {
            _vbmeta: vbmeta,
            descriptor_ptrs,
            index: 0,
        })
    }

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
    unsafe fn extract_descriptor(raw_descriptor: *const AvbDescriptor) -> Option<Descriptor<'a>> {
        // Transform header to host-endian.
        let mut descriptor = AvbDescriptor {
            tag: 0,
            num_bytes_following: 0,
        };
        // SAFETY: both args point to valid `AvbDescriptor` objects.
        if !unsafe { avb_descriptor_validate_and_byteswap(raw_descriptor, &mut descriptor) } {
            return None;
        }

        // Extract the descriptor header and contents bytes.
        // SAFETY: `raw_descriptor` points to the header plus `num_bytes_following` bytes.
        let contents = unsafe {
            from_raw_parts(
                raw_descriptor as *const u8,
                size_of::<AvbDescriptor>()
                    .checked_add(descriptor.num_bytes_following.try_into().ok()?)?,
            )
        };

        match descriptor.tag.try_into().ok()? {
            AvbDescriptorTag::AVB_DESCRIPTOR_TAG_PROPERTY => Some(Descriptor::Property),
            AvbDescriptorTag::AVB_DESCRIPTOR_TAG_HASHTREE => Some(Descriptor::Hashtree),
            AvbDescriptorTag::AVB_DESCRIPTOR_TAG_HASH => {
                Some(Descriptor::Hash(HashDescriptor::new(contents)?))
            }
            AvbDescriptorTag::AVB_DESCRIPTOR_TAG_KERNEL_CMDLINE => {
                Some(Descriptor::KernelCommandline)
            }
            AvbDescriptorTag::AVB_DESCRIPTOR_TAG_CHAIN_PARTITION => {
                Some(Descriptor::ChainPartition)
            }
            _ => None,
        }
    }

    /// Resets the iterator to the first descriptor.
    ///
    /// This is slightly more efficient than dropping and re-creating a new iterator since each
    /// new iterator has to do some allocation and bookkeeping.
    ///
    /// This is safe because each returned `Descriptor` is a read-only view over the data in the
    /// vbmeta image so it's OK to hold multiple `Descriptors` over the same underlying data.
    pub fn reset(&mut self) {
        self.index = 0;
    }
}

impl<'a> Iterator for DescriptorIterator<'a> {
    type Item = Descriptor<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        // Grab the next raw descriptor pointer and advance the index for next time.
        let raw_descriptor = *self.descriptor_ptrs.get(self.index)?;
        self.index += 1;

        // SAFETY:
        // * `raw_descriptor` was validated when we saved it in `new()`, so we know it points to a
        //   valid `AvbDescriptor` within the verified vbmeta image.
        // * `raw_descriptor` always points inside `self._vbmeta.data()` which we are borrowing,
        //   so the pointed contents will not change for at least `'a`.
        match unsafe { Self::extract_descriptor(raw_descriptor) } {
            // If we failed to parse this descriptor, return `Unknown` rather than `None` so that
            // the caller can keep iterating. libavb has already verified that the descriptors are
            // valid in `avb_descriptor_foreach()` so this particular descriptor must just be a
            // format we don't yet understand.
            None => Some(Descriptor::Unknown),
            d => d,
        }
    }
}

/// Adds the given descriptor to the `Vec` pointed to by `user_data`.
///
/// Serves as a C callback for use with `avb_descriptor_foreach()`.
///
/// # Returns
/// Always returns true to continue iterating over the descriptors.
///
/// # Safety
/// * `descriptor` must point to a valid `AvbDescriptor` (guaranteed by `avb_descriptor_foreach()`).
/// * `user_data` must point to a valid `Vec<*const AvbDescriptor>` with no other concurrent access.
unsafe extern "C" fn fill_descriptor_ptrs_vec(
    descriptor: *const AvbDescriptor,
    user_data: *mut c_void,
) -> bool {
    // SAFETY: `user_data` gives exclusive access to a valid `Vec<*const AvbDescriptor>`.
    let descriptor_ptrs = unsafe { (user_data as *mut Vec<*const AvbDescriptor>).as_mut() };

    // We never pass a NULL `user_data` into this callback so we know this will succeed.
    let descriptor_ptrs = descriptor_ptrs.unwrap();

    descriptor_ptrs.push(descriptor);
    true
}
