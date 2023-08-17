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

//! Utility helper APIs.

use crate::IoError;
use core::ffi::{c_char, c_void, CStr};

/// Converts a non-NULL `ptr` to `Ok(ptr)`, NULL to `Err(IoError::Io)`.
pub(crate) fn check_nonnull<T>(ptr: *const T) -> Result<*const T, IoError> {
    match ptr.is_null() {
        true => Err(IoError::Io),
        false => Ok(ptr),
    }
}

/// Converts a non-NULL `ptr` to `Ok(ptr)`, NULL to `Err(IoError::Io)`.
pub(crate) fn check_nonnull_mut<T>(ptr: *mut T) -> Result<*mut T, IoError> {
    match ptr.is_null() {
        true => Err(IoError::Io),
        false => Ok(ptr),
    }
}

/// Converts a C-string to a Rust `&str`.
///
/// # Args
/// * `ptr`: pointer to the C-string source.
///
/// # Returns
/// A `&str` wrapping the data from `ptr`, or `IoError` if `ptr` was `NULL` or not valid UTF-8.
///
/// # Safety
/// `ptr` must either be `NULL` or:
/// * point to a nul-terminated string within its allocation
/// * the string contents must not be modified while the returned `&str` exists
///
/// All pointers provided by libavb meet this criteria.
pub(crate) unsafe fn cstr_to_str<'a>(ptr: *const c_char) -> Result<&'a str, IoError> {
    // SAFETY:
    // * we check that the pointer is non-NULL
    // * the caller is required to meet the function safety conditions
    let c_str = unsafe { CStr::from_ptr(check_nonnull(ptr)?) };
    c_str.to_str().map_err(|_| IoError::Io)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::ffi::CString;
    use std::ptr;

    #[test]
    fn test_cstr_to_str() {
        let source = CString::new("abc123").unwrap();
        assert_eq!(unsafe { cstr_to_str(source.as_ptr()) }, Ok("abc123"));
    }

    #[test]
    fn test_cstr_to_str_null() {
        let null = ptr::null();
        assert_eq!(unsafe { cstr_to_str(null) }, Err(IoError::Io));
    }
}
