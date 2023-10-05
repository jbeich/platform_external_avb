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

//! Verification APIs.
//!
//! This module is responsible for all the conversions required to pass information between
//! libavb and Rust for verifying images.

use crate::{error::result_to_io_enum, IoError};
use avb_bindgen::{AvbIOResult, AvbOps};
use core::{
    cmp::min,
    ffi::{c_char, c_void, CStr},
    ptr, slice,
};

/// Common `Result` type for `IoError` errors.
type Result<T> = core::result::Result<T, IoError>;

/// Base implementation-provided callbacks for verification.
///
/// See libavb `AvbOps` for more complete documentation.
pub trait Ops {
    /// Reads data from the requested partition on disk.
    ///
    /// # Arguments
    /// * `partition`: partition name to read from.
    /// * `offset`: offset in bytes within the partition to read from; a positive value indicates an
    ///             offset from the partition start, a negative value indicates a backwards offset
    ///             from the partition end.
    /// * `buffer`: buffer to read data into.
    ///
    /// # Returns
    /// The number of bytes actually read into `buffer` or an `IoError`. Reading less than
    /// `buffer.len()` bytes is only allowed if the end of the partition was reached.
    fn read_from_partition(
        &mut self,
        partition: &CStr,
        offset: i64,
        buffer: &mut [u8],
    ) -> Result<usize>;

    /// Returns a reference to preloaded partition contents.
    ///
    /// This is an optional optimization if a partition has already been loaded to provide libavb
    /// with a reference to the data rather than copying it as `read_from_partition()` would.
    ///
    /// May be left unimplemented if preloaded partitions are not used.
    ///
    /// # Arguments
    /// * `partition`: partition name to read from.
    ///
    /// # Returns
    /// * A reference to the entire partition contents if the partition has been preloaded.
    /// * `Err<IoError::NotImplemented>` if the requested partition has not been preloaded;
    ///   verification will next attempt to load the partition via `read_from_partition()`.
    /// * Any other `Err<IoError>` if an error occurred; verification will exit immediately.
    fn get_preloaded_partition(&mut self, partition: &CStr) -> Result<&[u8]> {
        Err(IoError::NotImplemented)
    }

    /// Checks if the given public key is valid for vbmeta image signing.
    ///
    /// # Arguments
    /// * `public_key`: the public key.
    /// * `public_key_metadata`: public key metadata set by the `--public_key_metadata` arg in
    ///                          `avbtool`, or None if no metadata was provided.
    ///
    /// # Returns
    /// True if the given key is valid, false if it is not, `IoError` on error.
    fn validate_vbmeta_public_key(
        &mut self,
        public_key: &[u8],
        public_key_metadata: Option<&[u8]>,
    ) -> Result<bool>;
}

/// Helper to pass user-provided `Ops` through libavb via the `user_data` pointer.
///
/// This is a bit tricky in Rust, we can't just cast `Ops` to `void*` and back directly because
/// `Ops` is a trait to be implemented by the user, which means we don't know the concrete type
/// at this point and must use dynamic dispatch.
///
/// However, dynamic dispatch in Rust requires a "fat pointer" (2 pointers) which cannot be cast to
/// a single `void*`. So instead, we wrap the dynamic dispatch inside this struct which _can_ be
/// represented as a single `void*`, and then we can unwrap it again to fetch the original
/// `&dyn Ops`.
///
/// A more typical approach is to use `Box` to heap-allocate the `&dyn` and then pass the `Box`
/// around, but we want to avoid allocation as much as possible.
///
/// Control flow:
/// ```
///         user                             libavb_rs                        libavb
/// -----------------------------------------------------------------------------------------------
/// create `Ops` (Rust) with
/// callback implementations
///                           ---->
///                                  `UserData::new()` wraps:
///                                  `Ops` (Rust/fat) ->
///                                  `UserData` (Rust/thin)
///
///                                  `create_avb_ops()` makes
///                                  `AvbOps` (C) containing:
///                                  1. `UserData*` (C)
///                                  2. our callbacks (C)
///                                                            ---->
///                                                                   execute `AvbOps` (C)
///                                                                   callbacks as needed
///                                                            <----
///                                  `as_ops()` unwraps:
///                                  `AvbOps` (C) ->
///                                  `UserData` (Rust/thin) ->
///                                  `Ops` (Rust/fat)
///
///                                  Convert callback data to
///                                  safe Rust
///                           <----
/// perform `Ops` (Rust)
/// callback
/// ```
struct UserData<'a>(&'a mut dyn Ops);

impl<'a> UserData<'a> {
    fn new(ops: &'a mut impl Ops) -> Self {
        Self(ops)
    }

    /// Creates the `AvbOps` with a mutable pointer to this `UserData` to pass into libavb.
    ///
    /// # Safety
    /// The returned `AvbOps` contains a mutable pointer to this `UserData`, which means the caller
    /// must manually enforce the rules around mutable borrows and lifetimes.
    ///
    /// In particular, this `UserData`:
    /// * must remain alive and unmoved while the returned `AvbOps` exists, or it will result in
    ///   a dangling pointer
    /// * must not be directly accessed (including the contained `Ops`) while the returned `AvbOps`
    ///   exists, or it will violate Rust's mutable borrowing rules
    unsafe fn create_avb_ops(&mut self) -> AvbOps {
        AvbOps {
            // Rust won't transitively cast so we need to cast twice manually, but the compiler is
            // smart enough to deduce the types we need.
            user_data: self as *mut _ as *mut _,
            ab_ops: ptr::null_mut(),  // Deprecated, no need to support.
            atx_ops: ptr::null_mut(), // TODO: support optional ATX.
            read_from_partition: Some(read_from_partition),
            get_preloaded_partition: Some(get_preloaded_partition),
            write_to_partition: None, // Not needed, only used for deprecated A/B.
            validate_vbmeta_public_key: Some(validate_vbmeta_public_key),
            // TODO: add callback wrappers for the remaining API.
            read_rollback_index: None,
            write_rollback_index: None,
            read_is_device_unlocked: None,
            get_unique_guid_for_partition: None,
            get_size_of_partition: None,
            read_persistent_value: None,
            write_persistent_value: None,
            validate_public_key_for_partition: None,
        }
    }
}

/// Extracts the user-provided `Ops` from a raw `AvbOps`.
///
/// # Arguments
/// * `avb_ops`: The raw `AvbOps` pointer used by libavb.
///
/// # Returns
/// The Rust `Ops` extracted from `avb_ops.user_data`.
///
/// # Safety
/// Only call this function on an `AvbOps` created via `create_avb_ops()`.
///
/// Additionally, this should be considered a mutable borrow of the contained `Ops`:
/// * do not return back to libavb while still holding the returned reference, or it will result
///   in a dangling reference
/// * do not call this again until the previous `Ops` goes out of scope, or it will violate Rust's
///   mutable borrowing rules
///
/// In practice, these conditions are met since we call this exactly once in each callback
/// to extract the `Ops`, and drop it at callback completion.
unsafe fn as_ops<'a>(avb_ops: *mut AvbOps) -> Result<&'a mut dyn Ops> {
    // SAFETY: we created this AvbOps object and passed it to libavb so we know it meets all
    // the criteria for `as_mut()`.
    let avb_ops = unsafe { avb_ops.as_mut() }.ok_or(IoError::Io)?;
    // Cast the void* `user_data` back to a UserData*.
    let user_data = avb_ops.user_data as *mut UserData;
    // SAFETY: we created this UserData object and passed it to libavb so we know it meets all
    // the criteria for `as_mut()`.
    Ok(unsafe { user_data.as_mut() }.ok_or(IoError::Io)?.0)
}

/// Converts a non-NULL `ptr` to `()`, NULL to `Err(IoError::Io)`.
fn check_nonnull<T>(ptr: *const T) -> Result<()> {
    match ptr.is_null() {
        true => Err(IoError::Io),
        false => Ok(()),
    }
}

/// Wraps a callback to convert the given `Result<>` to raw `AvbIOResult` for libavb.
///
/// See corresponding `try_*` function docs.
unsafe extern "C" fn read_from_partition(
    ops: *mut AvbOps,
    partition: *const c_char,
    offset: i64,
    num_bytes: usize,
    buffer: *mut c_void,
    out_num_read: *mut usize,
) -> AvbIOResult {
    result_to_io_enum(try_read_from_partition(
        ops,
        partition,
        offset,
        num_bytes,
        buffer,
        out_num_read,
    ))
}

/// Bounces the C callback into the user-provided Rust implementation.
///
/// # Safety
/// * `ops` must have been created via `create_avb_ops()`.
/// * `partition` must adhere to the requirements of `CStr::from_ptr()`.
/// * `buffer` must adhere to the requirements of `slice::from_raw_parts_mut()`.
/// * `out_num_read` must adhere to the requirements of `ptr::write()`.
unsafe fn try_read_from_partition(
    ops: *mut AvbOps,
    partition: *const c_char,
    offset: i64,
    num_bytes: usize,
    buffer: *mut c_void,
    out_num_read: *mut usize,
) -> Result<()> {
    check_nonnull(partition)?;
    check_nonnull(buffer)?;
    check_nonnull(out_num_read)?;

    // Initialize the output variables first in case something fails.
    // SAFETY:
    // * we've checked that the pointer is non-NULL.
    // * libavb gives us a properly-allocated `out_num_read`.
    unsafe { ptr::write(out_num_read, 0) };

    // SAFETY:
    // * we only use `ops` objects created via `create_avb_ops()` as required.
    // * `ops` is only extracted once and is dropped at the end of the callback.
    let ops = unsafe { as_ops(ops) }?;
    // SAFETY:
    // * we've checked that the pointer is non-NULL.
    // * libavb gives us a properly-allocated and nul-terminated `partition`.
    // * the string contents are not modified while the returned `&CStr` exists.
    // * the returned `&CStr` is not held past the scope of this callback.
    let partition = unsafe { CStr::from_ptr(partition) };
    // SAFETY:
    // * we've checked that the pointer is non-NULL.
    // * libavb gives us a properly-allocated `buffer` with size `num_bytes`.
    // * we only access the contents via the returned slice.
    // * the returned slice is not held past the scope of this callback.
    let buffer = unsafe { slice::from_raw_parts_mut(buffer as *mut u8, num_bytes) };

    let bytes_read = ops.read_from_partition(partition, offset, buffer)?;
    // SAFETY:
    // * we've checked that the pointer is non-NULL.
    // * libavb gives us a properly-allocated `out_num_read`.
    unsafe { ptr::write(out_num_read, bytes_read) };
    Ok(())
}

/// Wraps a callback to convert the given `Result<>` to raw `AvbIOResult` for libavb.
///
/// See corresponding `try_*` function docs.
unsafe extern "C" fn get_preloaded_partition(
    ops: *mut AvbOps,
    partition: *const c_char,
    num_bytes: usize,
    out_pointer: *mut *mut u8,
    out_num_bytes_preloaded: *mut usize,
) -> AvbIOResult {
    result_to_io_enum(try_get_preloaded_partition(
        ops,
        partition,
        num_bytes,
        out_pointer,
        out_num_bytes_preloaded,
    ))
}

/// Bounces the C callback into the user-provided Rust implementation.
///
/// # Safety
/// * `ops` must have been created via `create_avb_ops()`.
/// * `partition` must adhere to the requirements of `CStr::from_ptr()`.
/// * `out_pointer` and `out_num_bytes_preloaded` must adhere to the requirements of `ptr::write()`.
/// * `out_pointer` will become an alias to the `ops` preloaded partition data, so the preloaded
///   data must remain valid and unmodified while `out_pointer` exists.
unsafe fn try_get_preloaded_partition(
    ops: *mut AvbOps,
    partition: *const c_char,
    num_bytes: usize,
    out_pointer: *mut *mut u8,
    out_num_bytes_preloaded: *mut usize,
) -> Result<()> {
    check_nonnull(partition)?;
    check_nonnull(out_pointer)?;
    check_nonnull(out_num_bytes_preloaded)?;

    // Initialize the output variables first in case something fails.
    // SAFETY:
    // * we've checked that the pointers are non-NULL.
    // * libavb gives us properly-aligned and sized `out` vars.
    unsafe {
        ptr::write(out_pointer, ptr::null_mut());
        ptr::write(out_num_bytes_preloaded, 0);
    }

    // SAFETY:
    // * we only use `ops` objects created via `create_avb_ops()` as required.
    // * `ops` is only extracted once and is dropped at the end of the callback.
    let ops = unsafe { as_ops(ops) }?;
    // SAFETY:
    // * we've checked that the pointer is non-NULL.
    // * libavb gives us a properly-allocated and nul-terminated `partition`.
    // * the string contents are not modified while the returned `&CStr` exists.
    // * the returned `&CStr` is not held past the scope of this callback.
    let partition = unsafe { CStr::from_ptr(partition) };

    match ops.get_preloaded_partition(partition) {
        // SAFETY:
        // * we've checked that the pointers are non-NULL.
        // * libavb gives us properly-aligned and sized `out` vars.
        Ok(contents) => unsafe {
            ptr::write(
                out_pointer,
                // Warning: we are casting an immutable &[u8] to a mutable *u8. If libavb actually
                // modified these contents this could cause undefined behavior, but it just reads.
                // TODO: can we change the libavb API to take a const*?
                contents.as_ptr() as *mut u8,
            );
            ptr::write(
                out_num_bytes_preloaded,
                // Truncate here if necessary, we may have more preloaded data than libavb needs.
                min(contents.len(), num_bytes),
            );
        },
        // No-op if this partition is not preloaded, we've already reset the out variables to
        // indicate preloaded data is not available.
        Err(IoError::NotImplemented) => (),
        Err(e) => return Err(e),
    };
    Ok(())
}

/// Wraps a callback to convert the given `Result<>` to raw `AvbIOResult` for libavb.
///
/// See corresponding `try_*` function docs.
unsafe extern "C" fn validate_vbmeta_public_key(
    ops: *mut AvbOps,
    public_key_data: *const u8,
    public_key_length: usize,
    public_key_metadata: *const u8,
    public_key_metadata_length: usize,
    out_is_trusted: *mut bool,
) -> AvbIOResult {
    result_to_io_enum(try_validate_vbmeta_public_key(
        ops,
        public_key_data,
        public_key_length,
        public_key_metadata,
        public_key_metadata_length,
        out_is_trusted,
    ))
}

/// Bounces the C callback into the user-provided Rust implementation.
///
/// # Safety
/// * `ops` must have been created via `create_avb_ops()`.
/// * `public_key_*` args must adhere to the requirements of `slice::from_raw_parts()`.
/// * `out_is_trusted` must adhere to the requirements of `ptr::write()`.
unsafe fn try_validate_vbmeta_public_key(
    ops: *mut AvbOps,
    public_key_data: *const u8,
    public_key_length: usize,
    public_key_metadata: *const u8,
    public_key_metadata_length: usize,
    out_is_trusted: *mut bool,
) -> Result<()> {
    check_nonnull(public_key_data)?;
    check_nonnull(out_is_trusted)?;

    // Initialize the output variables first in case something fails.
    // SAFETY:
    // * we've checked that the pointer is non-NULL.
    // * libavb gives us a properly-allocated `out_is_trusted`.
    unsafe { ptr::write(out_is_trusted, false) };

    // SAFETY:
    // * we only use `ops` objects created via `create_avb_ops()` as required.
    // * `ops` is only extracted once and is dropped at the end of the callback.
    let ops = unsafe { as_ops(ops) }?;
    // SAFETY:
    // * we've checked that the pointer is non-NULL.
    // * libavb gives us a properly-allocated `public_key_data` with size `public_key_length`.
    // * we only access the contents via the returned slice.
    // * the returned slice is not held past the scope of this callback.
    let public_key = unsafe { slice::from_raw_parts(public_key_data, public_key_length) };
    let metadata = check_nonnull(public_key_metadata).ok().map(
        // SAFETY:
        // * we've checked that the pointer is non-NULL.
        // * libavb gives us a properly-allocated `public_key_metadata` with size
        //   `public_key_metadata_length`.
        // * we only access the contents via the returned slice.
        // * the returned slice is not held past the scope of this callback.
        |_| unsafe { slice::from_raw_parts(public_key_metadata, public_key_metadata_length) },
    );

    let trusted = ops.validate_vbmeta_public_key(public_key, metadata)?;

    // SAFETY:
    // * we've checked that the pointer is non-NULL.
    // * libavb gives us a properly-allocated `out_is_trusted`.
    unsafe { ptr::write(out_is_trusted, trusted) };
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::HashMap;
    use std::ffi::CString;

    /// Ops implementation for testing.
    ///
    /// In addition to being used to exercise individual callback wrappers, this will be used for
    /// full verification tests so behavior needs to be correct.
    #[derive(Default)]
    struct TestOps {
        /// Partitions to "read" on request.
        pub partitions: HashMap<&'static str, Vec<u8>>,
        /// Preloaded partitions. Same functionality as `partitions`, just separated to be able
        /// to test reading and preloading callbacks independently.
        pub preloaded: HashMap<&'static str, Vec<u8>>,
        /// Vbmeta public keys as a map of {(key, metadata): trusted}. Querying unknown keys will
        /// return `IoError::Io`.
        pub vbmeta_keys: HashMap<(&'static [u8], Option<&'static [u8]>), bool>,
    }

    impl Ops for TestOps {
        fn read_from_partition(
            &mut self,
            partition: &CStr,
            offset: i64,
            buffer: &mut [u8],
        ) -> Result<usize> {
            let contents = self
                .partitions
                .get(partition.to_str()?)
                .ok_or(IoError::NoSuchPartition)?;

            // Negative offset means count backwards from the end.
            let offset = {
                if offset < 0 {
                    offset
                        .checked_add(i64::try_from(contents.len()).unwrap())
                        .unwrap()
                } else {
                    offset
                }
            };
            if offset < 0 {
                return Err(IoError::RangeOutsidePartition);
            }
            let offset = usize::try_from(offset).unwrap();

            if offset >= contents.len() {
                return Err(IoError::RangeOutsidePartition);
            }

            // Truncating is allowed for reads past the partition end.
            let end = min(offset.checked_add(buffer.len()).unwrap(), contents.len());
            let bytes_read = end - offset;

            buffer[..bytes_read].copy_from_slice(&contents[offset..end]);
            Ok(bytes_read)
        }

        fn get_preloaded_partition(&mut self, partition: &CStr) -> Result<&[u8]> {
            self.preloaded
                .get(partition.to_str()?)
                .ok_or(IoError::NotImplemented)
                .map(|vec| &vec[..])
        }

        fn validate_vbmeta_public_key(
            &mut self,
            public_key: &[u8],
            public_key_metadata: Option<&[u8]>,
        ) -> Result<bool> {
            self.vbmeta_keys
                .get(&(public_key, public_key_metadata))
                .ok_or(IoError::Io)
                .copied()
        }
    }

    /// Calls the `read_from_partition()` C callback the same way libavb would.
    fn call_read_from_partition(
        ops: &mut TestOps,
        partition: &str,
        offset: i64,
        num_bytes: usize,
        buffer: &mut [u8],
        out_num_read: &mut usize,
    ) -> AvbIOResult {
        let mut user_data = UserData(ops);
        // SAFETY: `user_data` remains in place and untouched while `avb_ops` exists.
        let mut avb_ops = unsafe { user_data.create_avb_ops() };
        let part_name = CString::new(partition).unwrap();

        // SAFETY: we've properly created and initialized all the raw pointers being passed into
        // this C function.
        unsafe {
            avb_ops.read_from_partition.unwrap()(
                &mut avb_ops,
                part_name.as_ptr(),
                offset,
                num_bytes,
                buffer.as_mut_ptr() as *mut c_void,
                out_num_read as *mut usize,
            )
        }
    }

    /// Calls the `get_preloaded_partition()` C callback the same way libavb would.
    ///
    /// # Safety
    /// If `ops` provides preloaded data, `out_buffer` will become an alias to this data. The
    /// lifetime bounds will ensure `ops` outlives `out_buffer`, but the caller must ensure the
    /// preloaded data is not modified while `out_buffer` lives.
    unsafe fn call_get_preloaded_partition<'a, 'b>(
        ops: &'a mut TestOps,
        partition: &str,
        num_bytes: usize,
        out_buffer: &mut &'b mut [u8],
        out_num_bytes_preloaded: &mut usize,
    ) -> AvbIOResult
    where
        'a: 'b,
    {
        let mut user_data = UserData(ops);
        // SAFETY: `user_data` remains in place and untouched while `avb_ops` exists.
        let mut avb_ops = unsafe { user_data.create_avb_ops() };
        let part_name = CString::new(partition).unwrap();
        let mut out_ptr: *mut u8 = ptr::null_mut();

        // SAFETY:
        // * We've properly created and initialized all the raw pointers being passed in
        // * We've set up lifetimes such that the `TestOps` which owns the data will outlive
        //   `out_buffer` which wraps the data.
        let result = unsafe {
            avb_ops.get_preloaded_partition.unwrap()(
                &mut avb_ops,
                part_name.as_ptr(),
                num_bytes,
                &mut out_ptr,
                out_num_bytes_preloaded as *mut usize,
            )
        };

        // If preload failed, libavb will see the null buffer and go to `read_from_partition()`.
        // For our purposes we return `NO_SUCH_PARTITION` so we can detect and test this case.
        if out_ptr.is_null() {
            return AvbIOResult::AVB_IO_RESULT_ERROR_NO_SUCH_PARTITION;
        }

        // SAFETY: we've properly created the `out` variables.
        *out_buffer = unsafe { slice::from_raw_parts_mut(out_ptr, *out_num_bytes_preloaded) };
        result
    }

    /// Calls the `validate_vbmeta_public_key()` C callback the same way libavb would.
    fn call_validate_vbmeta_public_key(
        ops: &mut TestOps,
        public_key: &[u8],
        public_key_metadata: Option<&[u8]>,
        out_is_trusted: &mut bool,
    ) -> AvbIOResult {
        let mut user_data = UserData(ops);
        // SAFETY: `user_data` remains in place and untouched while `avb_ops` exists.
        let mut avb_ops = unsafe { user_data.create_avb_ops() };
        let (metadata_ptr, metadata_size) =
            public_key_metadata.map_or((ptr::null(), 0), |m| (m.as_ptr(), m.len()));

        // SAFETY: we've properly created and initialized all the raw pointers being passed in.
        unsafe {
            avb_ops.validate_vbmeta_public_key.unwrap()(
                &mut avb_ops,
                public_key.as_ptr(),
                public_key.len(),
                metadata_ptr,
                metadata_size,
                out_is_trusted,
            )
        }
    }

    #[test]
    fn test_read_from_partition() {
        let mut ops = TestOps::default();
        ops.partitions = HashMap::from([("foo", vec![1u8, 2u8, 3u8, 4u8])]);

        let mut buffer: [u8; 8] = [0; 8];
        let mut bytes_read: usize = 0;
        let result = call_read_from_partition(&mut ops, "foo", 0, 4, &mut buffer, &mut bytes_read);

        assert_eq!(result, AvbIOResult::AVB_IO_RESULT_OK);
        assert_eq!(bytes_read, 4);
        assert_eq!(buffer, [1, 2, 3, 4, 0, 0, 0, 0]);
    }

    #[test]
    fn test_read_from_partition_with_offset() {
        let mut ops = TestOps::default();
        ops.partitions = HashMap::from([("foo", vec![1u8, 2u8, 3u8, 4u8])]);

        let mut buffer: [u8; 8] = [0; 8];
        let mut bytes_read: usize = 0;
        let result = call_read_from_partition(&mut ops, "foo", 1, 2, &mut buffer, &mut bytes_read);

        assert_eq!(result, AvbIOResult::AVB_IO_RESULT_OK);
        assert_eq!(bytes_read, 2);
        assert_eq!(buffer, [2, 3, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn test_read_from_partition_negative_offset() {
        let mut ops = TestOps::default();
        ops.partitions = HashMap::from([("foo", vec![1u8, 2u8, 3u8, 4u8])]);

        let mut buffer: [u8; 8] = [0; 8];
        let mut bytes_read: usize = 0;
        let result = call_read_from_partition(&mut ops, "foo", -2, 2, &mut buffer, &mut bytes_read);

        assert_eq!(result, AvbIOResult::AVB_IO_RESULT_OK);
        assert_eq!(bytes_read, 2);
        assert_eq!(buffer, [3, 4, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn test_read_from_partition_truncate() {
        let mut ops = TestOps::default();
        ops.partitions = HashMap::from([("foo", vec![1u8, 2u8, 3u8, 4u8])]);

        let mut buffer: [u8; 8] = [0; 8];
        let mut bytes_read: usize = 0;
        let result = call_read_from_partition(&mut ops, "foo", 0, 8, &mut buffer, &mut bytes_read);

        assert_eq!(result, AvbIOResult::AVB_IO_RESULT_OK);
        assert_eq!(bytes_read, 4);
        assert_eq!(buffer, [1, 2, 3, 4, 0, 0, 0, 0]);
    }

    #[test]
    fn test_read_from_partition_unknown() {
        let mut ops = TestOps::default();
        ops.partitions = HashMap::from([("foo", vec![1u8, 2u8, 3u8, 4u8])]);

        let mut buffer: [u8; 8] = [0; 8];
        let mut bytes_read: usize = 10;
        let result = call_read_from_partition(&mut ops, "bar", 0, 8, &mut buffer, &mut bytes_read);

        assert_eq!(result, AvbIOResult::AVB_IO_RESULT_ERROR_NO_SUCH_PARTITION);
        assert_eq!(bytes_read, 0);
        assert_eq!(buffer, [0; 8]);
    }

    #[test]
    fn test_get_preloaded_partition() {
        let mut ops = TestOps::default();
        ops.preloaded = HashMap::from([("foo_preload", vec![1u8, 2u8, 3u8, 4u8])]);

        let mut contents: &mut [u8] = &mut [];
        let mut size: usize = 0;
        // SAFETY: preloaded data remain valid and unmodified while `contents` exists.
        let result = unsafe {
            call_get_preloaded_partition(&mut ops, "foo_preload", 4, &mut contents, &mut size)
        };

        assert_eq!(result, AvbIOResult::AVB_IO_RESULT_OK);
        assert_eq!(size, 4);
        assert_eq!(contents, [1, 2, 3, 4]);
    }

    #[test]
    fn test_get_preloaded_partition_truncate() {
        let mut ops = TestOps::default();
        ops.preloaded = HashMap::from([("foo_preload", vec![1u8, 2u8, 3u8, 4u8])]);

        let mut contents: &mut [u8] = &mut [];
        let mut size: usize = 0;
        // SAFETY: preloaded data remain valid and unmodified while `contents` exists.
        let result = unsafe {
            call_get_preloaded_partition(&mut ops, "foo_preload", 2, &mut contents, &mut size)
        };

        assert_eq!(result, AvbIOResult::AVB_IO_RESULT_OK);
        assert_eq!(size, 2);
        assert_eq!(contents, [1, 2]);
    }

    #[test]
    fn test_get_preloaded_partition_unknown() {
        let mut ops = TestOps::default();
        ops.preloaded = HashMap::from([("foo_preload", vec![1u8, 2u8, 3u8, 4u8])]);

        let mut contents: &mut [u8] = &mut [];
        let mut size: usize = 10;
        // SAFETY: requested preloaded data does not exist, no data alias is created.
        let result =
            unsafe { call_get_preloaded_partition(&mut ops, "bar", 4, &mut contents, &mut size) };

        assert_eq!(result, AvbIOResult::AVB_IO_RESULT_ERROR_NO_SUCH_PARTITION);
        assert_eq!(size, 0);
        assert_eq!(contents, []);
    }

    #[test]
    fn test_validate_vbmeta_public_key() {
        let mut ops = TestOps::default();
        ops.vbmeta_keys = HashMap::from([((b"testkey".as_ref(), None), true)]);

        let mut is_trusted = false;
        let result = call_validate_vbmeta_public_key(&mut ops, b"testkey", None, &mut is_trusted);

        assert_eq!(result, AvbIOResult::AVB_IO_RESULT_OK);
        assert!(is_trusted);
    }

    #[test]
    fn test_validate_vbmeta_public_key_with_metadata() {
        let mut ops = TestOps::default();
        ops.vbmeta_keys =
            HashMap::from([((b"testkey".as_ref(), Some(b"testmeta".as_ref())), true)]);

        let mut is_trusted = false;
        let result = call_validate_vbmeta_public_key(
            &mut ops,
            b"testkey",
            Some(b"testmeta"),
            &mut is_trusted,
        );

        assert_eq!(result, AvbIOResult::AVB_IO_RESULT_OK);
        assert!(is_trusted);
    }

    #[test]
    fn test_validate_vbmeta_public_key_rejected() {
        let mut ops = TestOps::default();
        ops.vbmeta_keys = HashMap::from([((b"testkey".as_ref(), None), false)]);

        let mut is_trusted = true;
        let result = call_validate_vbmeta_public_key(&mut ops, b"testkey", None, &mut is_trusted);

        assert_eq!(result, AvbIOResult::AVB_IO_RESULT_OK);
        assert!(!is_trusted);
    }

    #[test]
    fn test_validate_vbmeta_public_key_error() {
        let mut ops = TestOps::default();

        let mut is_trusted = true;
        let result = call_validate_vbmeta_public_key(&mut ops, b"testkey", None, &mut is_trusted);

        assert_eq!(result, AvbIOResult::AVB_IO_RESULT_ERROR_IO);
        assert!(!is_trusted);
    }
}
