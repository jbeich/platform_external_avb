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

use crate::VbmetaData;
use avb_bindgen::{
    avb_descriptor_get_all, avb_descriptor_validate_and_byteswap, avb_free, AvbDescriptor,
    AvbDescriptorTag,
};
use core::{ffi::c_void, mem::size_of, ptr::NonNull, slice::from_raw_parts};

/// A single descriptor.
// TODO(b/290110273): add support for full descriptor contents.
#[derive(Debug)]
pub enum Descriptor {
    /// Wraps `AvbPropertyDescriptor`.
    Property,
    /// Wraps `AvbHashtreeDescriptor`.
    Hashtree,
    /// Wraps `AvbHashDescriptor`.
    Hash,
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
/// Creating a descriptor iterator allocates a small amount of heap memory (~1 pointer per
/// descriptor).
pub struct DescriptorIterator<'a> {
    /// The vbmeta image we're iterating over; hold a borrow since we're going to have pointers
    /// pointing into this data.
    _vbmeta: &'a VbmetaData,
    /// Pointer to a list of all decriptors. libavb allocates this and gives us ownership, so must
    /// be explicitly freed when we are done with it.
    descriptors_ptr: NonNull<*const AvbDescriptor>,
    /// Slice around `descriptors_ptr` for easier usage.
    descriptors: &'a [*const AvbDescriptor],
    /// Next item to pull from `descriptors`.
    index: usize,
}

impl<'a> DescriptorIterator<'a> {
    /// Creates a new iterator over the descriptors in the given vbmeta image, or `None` on error.
    pub(crate) fn new(vbmeta: &'a VbmetaData) -> Option<Self> {
        let mut num_descriptors: usize = 0;
        let descriptors_ptr = NonNull::new(
            // SAFETY:
            // * `vbmeta.data()` is a valid vbmeta image.
            // * `num_descriptors` is a valid `usize`.
            // * if the returned pointer is non-NULL we immediately take ownership of it and will
            //   free the memory on drop.
            unsafe {
                avb_descriptor_get_all(
                    vbmeta.data().as_ptr(),
                    vbmeta.data().len(),
                    &mut num_descriptors,
                )
            },
        )?;

        Some(Self {
            _vbmeta: vbmeta,
            descriptors_ptr,
            // SAFETY: `descriptors_ptr` is a valid pointer, pointing to a single allocation
            // of `num_descriptors` descriptor pointers.
            descriptors: unsafe { from_raw_parts(descriptors_ptr.as_ptr(), num_descriptors) },
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
    /// `raw_descriptor` must point to a valid `AvbDescriptor` immediately followed by the number
    /// of data bytes indicated by `num_bytes_following`.
    unsafe fn extract_descriptor(raw_descriptor: *const AvbDescriptor) -> Option<Descriptor> {
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
        let _contents = unsafe {
            from_raw_parts(
                raw_descriptor as *const u8,
                size_of::<AvbDescriptor>()
                    .checked_add(descriptor.num_bytes_following.try_into().ok()?)?,
            )
        };

        match descriptor.tag.try_into().ok()? {
            AvbDescriptorTag::AVB_DESCRIPTOR_TAG_PROPERTY => Some(Descriptor::Property),
            AvbDescriptorTag::AVB_DESCRIPTOR_TAG_HASHTREE => Some(Descriptor::Hashtree),
            AvbDescriptorTag::AVB_DESCRIPTOR_TAG_HASH => Some(Descriptor::Hash),
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

impl<'a> Drop for DescriptorIterator<'a> {
    fn drop(&mut self) {
        // SAFETY: libavb gave us ownership of `descriptors_ptr` and requires us to `avb_free()` it
        // when done.
        unsafe { avb_free(self.descriptors_ptr.as_ptr() as *mut c_void) };
    }
}

impl<'a> Iterator for DescriptorIterator<'a> {
    type Item = Descriptor;

    fn next(&mut self) -> Option<Self::Item> {
        // Grab the next raw descriptor pointer and advance the index for next time.
        let raw_descriptor: *const AvbDescriptor = *self.descriptors.get(self.index)?;
        self.index += 1;

        // SAFETY: `raw_descriptor` points to a valid `AvbDescriptor` within the verified vbmeta
        // image.
        match unsafe { Self::extract_descriptor(raw_descriptor) } {
            // If we failed to parse this descriptor, return `Unknown` rather than `None` so that
            // the caller can keep iterating. libavb has already verified that the descriptors are
            // valid in `avb_descriptor_get_all()` so this particular descriptor must just be a
            // format we don't yet understand.
            None => Some(Descriptor::Unknown),
            d => d,
        }
    }
}
