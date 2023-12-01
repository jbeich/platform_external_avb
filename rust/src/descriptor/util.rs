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

//! Descriptor utilities.

/// Splits `size` bytes off the front of `data`.
///
/// This is a thin wrapper around `slice::split_at()` but it:
/// 1. Returns `None` rather than panicking if `data` is too small.
/// 2. Accepts a variety of `size` types since descriptors commonly use `u32` or `u64`.
///
/// # Arguments
/// * `data`: descriptor data.
/// * `size`: the number of bytes to pull off the front.
///
/// # Returns
/// A tuple containing (extracted_bytes, data_remainder) on success, or None if we couldn't get
/// `size` bytes out of `data`.
pub(super) fn extract_slice<T>(data: &[u8], size: T) -> Option<(&[u8], &[u8])>
where
    T: TryInto<usize>,
{
    let size: usize = size.try_into().ok()?;
    if size > data.len() {
        None
    } else {
        Some(data.split_at(size))
    }
}
