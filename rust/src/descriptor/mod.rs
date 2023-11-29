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
use avb_bindgen::{avb_descriptor_foreach, avb_descriptor_validate_and_byteswap, AvbDescriptor};
use core::{ffi::c_void, mem::size_of, slice::from_raw_parts};

/// A single descriptor.
pub enum Descriptor {
    // TODO: include the descriptor contents.
    Property,
    Hashtree,
    Hash,
    KernelCommandline,
    ChainPartition,
}

/// Iterator for accessing all the descriptors in a vbmeta image.
pub struct DescriptorIterator<'a> {
    index: usize,
    vbmeta: &'a VbmetaData,
}

impl<'a> DescriptorIterator<'a> {
    /// Creates a new iterator over the given vbmeta image.
    pub(crate) fn new(vbmeta: &'a VbmetaData) -> Self {
        Self { index: 0, vbmeta }
    }
}

impl<'a> Iterator for DescriptorIterator<'a> {
    type Item = Descriptor;

    // libavb has two ways to iterate over descriptors:
    // 1. `avb_descriptor_foreach()`: executes a callback on each descriptor.
    // 2. `avb_descriptor_get_all()`: allocates and returns an array of all descriptors.
    //
    // To avoid allocation we want to use #1, but there's no way to "pause" the callbacks and
    // resume later from the same place. So to accomplish this, we track which descriptor index
    // we're on and use the callbacks to count from the beginning on each call to `next()`.
    //
    // vbmeta images typically contain only a small number of descriptors so the inefficiency
    // of counting from the beginning each time shouldn't be noticeable.
    fn next(&mut self) -> Option<Self::Item> {
        let mut state = FindDescriptorState {
            count: self.index,
            descriptor: AvbDescriptor {
                tag: 0,
                num_bytes_following: 0,
            },
            contents: None,
        };

        // SAFETY:
        // * `vbmeta` wraps a valid vbmeta image which will not be modified while borrowed
        // * the user data is a valid `FindDescriptorState` as required by `find_descriptor()`
        unsafe {
            avb_descriptor_foreach(
                self.vbmeta.data().as_ptr(),
                self.vbmeta.data().len(),
                Some(find_descriptor),
                &mut state as *mut _ as *mut c_void,
            )
        };

        if state.contents.is_some() {
            // Advance the index for next time.
            self.index += 1;

            // TODO: parse the proper descriptor type.
            Some(Descriptor::Hash)
        } else {
            None
        }
    }
}

/// State for `find_descriptor()` iteration.
struct FindDescriptorState<'a> {
    /// How many more descriptors to count before our target.
    count: usize,
    /// The resulting descriptor header in host-endian order.
    descriptor: AvbDescriptor,
    /// The resulting descriptor bytes, if found.
    contents: Option<&'a [u8]>,
}

/// C callback wrapper for `avb_descriptor_foreach()`.
///
/// # Safety
/// See `try_find_descriptor()`.
unsafe extern "C" fn find_descriptor(
    descriptor: *const AvbDescriptor,
    user_data: *mut c_void,
) -> bool {
    // SAFETY: see `try_find_descriptor()`.
    match unsafe { try_find_descriptor(descriptor, user_data) } {
        Some(false) => true, // We haven't found it yet, keep iterating.
        _ => false,          // Either we found it or hit an error, stop iterating.
    }
}

/// Locates the descriptor in a vbmeta image.
///
/// libavb will call this function on each descriptor in order, which we use to update the state
/// in order to find the descriptor at a specific index.
///
/// # Arguments
/// * `descriptor`: an `AvbDescriptor` inside the vbmeta image.
/// * `user_data`: a `FindDescriptorState` object.
///
/// # Returns
/// * `Some(true)` if the desired descriptor was found
/// * `Some(false)` to keep iterating
/// * `None` on error
///
/// # Safety
/// * `descriptor` must be a valid `AvbDescriptor` object which must also wrap a valid descriptor
///   of size indicated in the header. Both the `AvbDescriptor` and subsequent data must remain
//    unmodified while the extracted contents slice exists.
/// * `user_data` must be a valid `FindDescriptorState` object with no other concurrent access.
unsafe fn try_find_descriptor(
    descriptor: *const AvbDescriptor,
    user_data: *mut c_void,
) -> Option<bool> {
    // SAFETY: `user_data` is a valid `FindDescriptorState` and we have exclusive ownership.
    let state = unsafe { (user_data as *mut FindDescriptorState).as_mut() }?;

    // When count reaches 0, we found the target descriptor.
    if state.count == 0 {
        // `descriptor` fields are big-endian, make sure to byteswap before using them.
        // SAFETY: `descriptor` and `state.descriptor` both point to valid `AvbDescriptor` objects.
        if !unsafe { avb_descriptor_validate_and_byteswap(descriptor, &mut state.descriptor) } {
            return None;
        }

        // SAFETY: `descriptor` contents include the header plus `num_bytes_following` bytes.
        state.contents = Some(unsafe {
            from_raw_parts(
                descriptor as *const u8,
                size_of::<AvbDescriptor>()
                    .checked_add(state.descriptor.num_bytes_following.try_into().ok()?)?,
            )
        });

        // We found the one we were looking for.
        return Some(true);
    }

    // Count down and try the next one.
    state.count -= 1;
    Some(false)
}
