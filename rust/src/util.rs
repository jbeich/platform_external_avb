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
//!
//! Some APIs that convert types from C to Rust take in a `lifetime_` reference argument. This arg
//! can be any type, and is only used to tell the compiler how to set the lifetime of the returned
//! reference. Since we have no way of automatically determining lifetimes from C types, it's up to
//! the caller to do this correctly.
//!
//! For example, if we are in a libavb callback where a C-string is only valid until we return
//! control back to libavb, the lifetime should be the scope of the callback function:
//!
//! ```
//! fn libavb_callback(ptr: *const c_char) {
//!   // The type of this object doesn't matter, it's only used to set the lifetime.
//!   let lifetime = ();
//!
//!   // The returned str is now tied to `lifetime` and the compiler will properly prevent
//!   // you from trying to hang onto it after this function returns.
//!   let s = unsafe { cstr_to_str(ptr, &lifetime) };
//! }
//! ```
//!
//! This explicit lifetime assignment is better than using `'static`, because we get some compiler
//! protection in cases when attempting to hold onto the resulting object longer than the source:
//!
//! ```compile_fail
//! let result = {
//!   let source = CString::new("abc123").unwrap();  // The source of our data.
//!   unsafe { cstr_to_str(source.as_ptr(), &source) }  // Tie `result` to `source` lifetime.
//! };
//! println!("result is out of scope! {result:?}");  // Compile fail since `source` is gone.
//! ```

use crate::IoError;
use core::{
    ffi::{c_char, c_void, CStr},
    ptr, slice,
};

/// Converts a C-string to a Rust `&str`.
///
/// # Args
/// * `ptr`: pointer to the C-string source.
/// * `lifetime_`: lifetime to assign the returned `&str`.
///
/// # Returns
/// A `&str` wrapping the data from `ptr`, or `IoError` if `ptr` was `NULL` or not valid UTF-8.
///
/// # Safety
/// `ptr` must either be `NULL` or:
/// * point to a nul-terminated string within its allocation
/// * the string contents must not be modified while the returned `&str` exists
///
/// These conditions must hold for at least the given `lifetime_`.
///
/// All pointers provided by libavb meet this criteria.
pub unsafe fn cstr_to_str<'a, L>(ptr: *const c_char, lifetime_: &'a L) -> Result<&'a str, IoError> {
    if ptr.is_null() {
        return Err(IoError::Io);
    }

    // SAFETY:
    // * we've checked that the pointer is non-NULL
    // * the caller is required to meet the function safety conditions
    let c_str = unsafe { CStr::from_ptr(ptr) };
    c_str.to_str().map_err(|_| IoError::Io)
}

/// Converts a C buffer (pointer + size) to a mutable Rust byte slice.
///
/// # Args
/// * `ptr`: pointer to the buffer data.
/// * `size`: buffer size in bytes.
/// * `lifetime_`: lifetime to assign the returned slice.
///
/// # Returns
/// A byte slice wrapping the given buffer, or `IoError` if `ptr` was `NULL`.
///
/// # Safety
/// `ptr` must either be `NULL` or:
/// * point to a valid single allocation of at least `size` bytes
/// * the buffer contents may only be accessed via the returned slice while it exists
///
/// These conditions must hold for at least the given `lifetime_`.
///
/// All pointers provided by libavb meet this criteria.
pub unsafe fn buffer_to_slice_mut<'a, L>(
    ptr: *mut u8,
    size: usize,
    lifetime_: &'a L,
) -> Result<&'a mut [u8], IoError> {
    if ptr.is_null() {
        return Err(IoError::Io);
    }

    // SAFETY:
    // * we've checked that the pointer is non-NULL
    // * the caller is required to meet the function safety conditions
    let ret = unsafe { slice::from_raw_parts_mut(ptr, size) };
    Ok(ret)
}

/// Writes to the value pointed to by a C pointer.
///
/// # Args
/// * `ptr`: pointer to the data to write.
/// * `value`: value to write.
///
/// # Returns
/// Unit on success, `IoError` if `ptr` was `NULL`.
///
/// # Safety
/// `ptr` must either be `NULL` or:
/// * point to a valid single allocation of at least `T` size
/// * be properly aligned for type `T`
/// * the contents must not be accessed concurrently with this function
///
/// All pointers provided by libavb meet this criteria.
pub unsafe fn write_checked<T>(ptr: *mut T, value: T) -> Result<(), IoError> {
    if ptr.is_null() {
        return Err(IoError::Io);
    }

    // SAFETY:
    // * we've checked that the pointer is non-NULL
    // * the caller is required to meet the function safety conditions
    unsafe {
        ptr::write(ptr, value);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::ffi::CString;

    #[test]
    fn test_cstr_to_str() {
        let source = CString::new("abc123").unwrap();
        assert_eq!(
            unsafe { cstr_to_str(source.as_ptr(), &source) },
            Ok("abc123")
        );
    }

    #[test]
    fn test_cstr_to_str_null() {
        let null = ptr::null();
        assert_eq!(unsafe { cstr_to_str(null, &null) }, Err(IoError::Io));
    }

    #[test]
    fn test_cstr_to_str_lifetime() {
        let source = CString::new("abc123").unwrap();
        {
            // A lifetime we know to be shorter than the source is OK.
            let lifetime = ();
            assert_eq!(
                unsafe { cstr_to_str(source.as_ptr(), &lifetime) },
                Ok("abc123")
            );
        }
    }

    #[test]
    fn test_buffer_to_slice_mut() {
        let mut source = [0u8, 1u8, 2u8, 3u8];
        assert_eq!(
            unsafe { buffer_to_slice_mut(source.as_mut_ptr(), source.len(), &source) },
            Ok([0u8, 1u8, 2u8, 3u8].as_mut())
        );
    }

    #[test]
    fn test_buffer_to_slice_mut_null() {
        let null = ptr::null_mut::<u8>();
        assert_eq!(
            unsafe { buffer_to_slice_mut(null, 10, &null) },
            Err(IoError::Io)
        );
    }

    #[test]
    fn test_buffer_to_slice_mut_lifetime() {
        let mut source = [0u8, 1u8, 2u8, 3u8];
        {
            // A lifetime we know to be shorter than the source is OK.
            let lifetime = ();
            assert_eq!(
                unsafe { buffer_to_slice_mut(source.as_mut_ptr(), source.len(), &lifetime) },
                Ok([0u8, 1u8, 2u8, 3u8].as_mut())
            );
        }
    }

    #[test]
    fn test_write_checked_u8() {
        let mut val = 0u8;
        assert!(unsafe { write_checked(&mut val as *mut u8, 10) }.is_ok());
        assert_eq!(val, 10);
    }

    #[test]
    fn test_write_checked_i32() {
        let mut val = 0i32;
        assert!(unsafe { write_checked(&mut val as *mut i32, -1000) }.is_ok());
        assert_eq!(val, -1000);
    }

    #[test]
    fn test_write_checked_null() {
        let null = ptr::null_mut::<u8>();
        assert_eq!(
            unsafe { write_checked(ptr::null_mut(), 10) },
            Err(IoError::Io)
        );
    }
}
