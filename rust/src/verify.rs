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

use crate::{
    error::result_to_io_enum,
    util::{buffer_to_slice_mut, cstr_to_str, write_checked},
    IoError,
};
use avb_bindgen::{AvbIOResult, AvbOps};
use core::{
    cmp::min,
    ffi::{c_char, c_void, CStr},
    ptr, slice,
};

/// Base implementation-provided callbacks for verification.
///
/// See libavb `AvbOps` for more complete documentation.
pub trait Ops {
    /// Reads data from the requested partition on disk.
    ///
    /// # Arguments
    /// * `partition`: partition to read from.
    /// * `offset`: offset in bytes within the partition to read from; a positive value indicates an
    ///             offset from the partition start, a negative value indicates a backwards offset
    ///             from the partition end.
    /// * `data`: buffer to read data into.
    ///
    /// # Returns
    /// The number of bytes actually read into `data` or an `IoError`. Reading less than
    /// `data.len()` bytes is only allowed if the end of the partition was reached.
    fn read_from_partition(
        &mut self,
        partition: &str,
        offset: i64,
        data: &mut [u8],
    ) -> Result<usize, IoError>;

    /// Returns a reference to preloaded partition contents.
    ///
    /// This is an optional optimization if a partition has already been loaded to provide libavb
    /// with a reference to the data rather than copying it as `read_from_partition()` would.
    ///
    /// May be left unimplemented if preloaded partitions are not used.
    ///
    /// # Arguments
    /// * `partition`: partition to read from.
    ///
    /// # Returns
    /// A reference to the entire partition contents, or None if the requested partition has not
    /// been preloaded or is unknown in which case libavb will fall back to `read_from_partition()`.
    ///
    /// # Safety
    /// This function will only be called during image verification, which returns a structure
    /// containing a copy of this reference. Until that verification result structure is dropped,
    /// the contents must remain valid and unmodified.
    unsafe fn get_preloaded_partition(&mut self, partition: &str) -> Option<&[u8]> {
        None
    }
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
struct UserData<'a>(&'a mut dyn Ops);

impl<'a> UserData<'a> {
    fn new(ops: &'a mut impl Ops) -> Self {
        Self(ops)
    }

    /// Creates the AvbOps with this user data to pass into libavb.
    ///
    /// # Safety
    /// This UserData object must stay valid and must not move while the returned AvbOps object
    /// still exists, as it contains a pointer to the UserData which will be left dangling if the
    /// UserData drops or moves.
    ///
    /// Since this is private functionality we can just be careful, but if this were a public API
    /// we'd probably need to come up with something more clever, possibly with Pinning.
    unsafe fn create_avb_ops(&mut self) -> AvbOps {
        AvbOps {
            // Rust won't transitively cast so we need to cast twice manually, but the compiler is
            // smart enough to deduce the types we need.
            user_data: self as *mut _ as *mut _,
            ab_ops: ptr::null_mut(),  // Deprecated, no need to support.
            atx_ops: ptr::null_mut(), // TODO: support optional ATX.
            read_from_partition: Some(read_from_partition),
            get_preloaded_partition: Some(get_preloaded_partition),
            // TODO: add callback wrappers for the remaining API.
            write_to_partition: None,
            validate_vbmeta_public_key: None,
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

    /// Extracts the user-provided Ops from a raw *AvbOps.
    ///
    /// # Safety
    /// Only call this function on an `AvbOps` object whose userdata was initialized to a valid
    /// UserData object via `create_avb_ops()`.
    ///
    /// The returned ref is only valid in the current libavb callback scope. Do not return back to
    /// libavb while still holding it.
    unsafe fn from_libavb(avb_ops: &'a *mut AvbOps) -> &'a mut dyn Ops {
        // SAFETY: we created this AvbOps object and passed it to libavb so we know it meets all
        // the criteria for `as_mut()`.
        let avb_ops = unsafe { avb_ops.as_mut() };
        // We created this non-null so can unconditionally unwrap.
        let avb_ops = avb_ops.unwrap();
        // Cast the void* `user_data` back to a UserData*.
        let user_data = avb_ops.user_data as *mut Self;
        // SAFETY: we created this UserData object and passed it to libavb so we know it meets all
        // the criteria for `as_mut()`.
        let user_data = unsafe { user_data.as_mut() };
        user_data.unwrap().0
    }
}

/// Bounces the C callback into the user-provided Rust implementation.
///
/// # Safety
/// * `ops` must have been created via `create_avb_ops()`.
/// * `partition` must adhere to the requirements of `cstr_to_str()`.
/// * `buffer` must adhere to the requirements of `buffer_to_slice_mut()`.
/// * `out_num_read` must adhere to the requirements of `write_checked()`.
unsafe extern "C" fn read_from_partition(
    ops: *mut AvbOps,
    partition: *const c_char,
    offset: i64,
    num_bytes: usize,
    buffer: *mut c_void,
    out_num_read: *mut usize,
) -> AvbIOResult {
    // Provided data is only valid for the lifetime of this function.
    let lifetime = ();
    result_to_io_enum((|| {
        // SAFETY:
        // * we only use `ops` objects created via `create_avb_ops()` as required.
        // * `ops` is not held past the scope of this callback.
        let ops = unsafe { UserData::from_libavb(&ops) };
        // SAFETY:
        // * libavb gives us a properly-allocated and nul-terminated `partition`.
        // * contents are valid for the entire `lifetime`.
        let partition = unsafe { cstr_to_str(partition, &lifetime) }?;
        // SAFETY:
        // * libavb gives us a properly-allocated `buffer` with size `num_bytes`.
        // * contents are valid for the entire `lifetime`.
        let buffer = unsafe { buffer_to_slice_mut(buffer, num_bytes, &lifetime) }?;
        let (bytes_read, result) = match ops.read_from_partition(partition, offset, buffer) {
            Ok(bytes_read) => (bytes_read, Ok(())),
            Err(e) => (0, Err(e)),
        };
        // SAFETY:
        // * libavb gives us a properly-aligned and sized `out_num_read`.
        unsafe { write_checked(out_num_read, bytes_read) }?;
        result
    })())
}

/// Bounces the C callback into the user-provided Rust implementation.
///
/// # Safety
/// * `ops` must have been created via `create_avb_ops()`.
/// * `partition` must adhere to the requirements of `cstr_to_str()`.
/// * `out_pointer` and `out_num_bytes_preloaded` must adhere to the requirements of
///   `write_checked()`.
unsafe extern "C" fn get_preloaded_partition(
    ops: *mut AvbOps,
    partition: *const c_char,
    num_bytes: usize,
    out_pointer: *mut *mut u8,
    out_num_bytes_preloaded: *mut usize,
) -> AvbIOResult {
    // Provided data is only valid for the lifetime of this function.
    let lifetime = ();
    result_to_io_enum((|| {
        // SAFETY:
        // * we only use `ops` objects created via `create_avb_ops()` as required.
        // * `ops` is not held past the scope of this callback.
        let ops = unsafe { UserData::from_libavb(&ops) };
        // SAFETY:
        // * libavb gives us a properly-allocated and nul-terminated `partition`.
        // * contents are valid for the entire `lifetime`.
        let partition = unsafe { cstr_to_str(partition, &lifetime) }?;
        // SAFETY: the callback implementer must adhere to the documented safety requirements,
        // in particular the returned contents must outlive the final verification data.
        let result = unsafe { ops.get_preloaded_partition(partition) };
        let (ptr, size) = match result {
            Some(contents) => {
                // Warning: we are casting an immutable &[u8] to a mutable *u8. If libavb actually
                // modified these contents this could cause undefined behavior, but it just reads.
                // TODO: can we change the libavb API to take a const*?
                let ptr = contents.as_ptr() as *mut u8;
                // Truncate here if necessary, we may have more preloaded data than libavb needs.
                let size = min(contents.len(), num_bytes);
                (ptr, size)
            }
            None => (ptr::null_mut(), 0),
        };
        // SAFETY:
        // * libavb gives us properly-aligned and sized `out` vars.
        unsafe {
            write_checked(out_pointer, ptr)?;
            write_checked(out_num_bytes_preloaded, size)?;
        }
        // We don't report any errors from this function for simplicity, if there's a problem e.g.
        // unknown partition name libavb will fall back to `read_from_partition()` and handle the
        // error there.
        Ok(())
    })())
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::HashMap;
    use std::ffi::CString;

    // Ops implementation for testing.
    //
    // In addition to being used to exercise individual callback wrappers, this will be used for
    // full verification tests so behavior needs to be correct.
    struct TestOps {
        // Partitions to "read" on request.
        pub partitions: HashMap<&'static str, Vec<u8>>,
        // Preloaded partitions. Same functionality as `partitions`, just separated to be able
        // to test reading and preloading callbacks independently.
        pub preloaded: HashMap<&'static str, Vec<u8>>,
    }

    impl Ops for TestOps {
        fn read_from_partition(
            &mut self,
            partition: &str,
            offset: i64,
            data: &mut [u8],
        ) -> Result<usize, IoError> {
            let contents = self
                .partitions
                .get(partition)
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
            let end = min(offset.checked_add(data.len()).unwrap(), contents.len());
            let bytes_read = end - offset;

            let (data, _) = data.split_at_mut(bytes_read);
            data.copy_from_slice(&contents[offset..end]);
            Ok(bytes_read)
        }

        // Safety: this object owns the returned data, so must outlive all uses of the data.
        unsafe fn get_preloaded_partition(&mut self, partition: &str) -> Option<&[u8]> {
            self.preloaded.get(partition).map(|vec| &vec[..])
        }
    }

    // Calls the `read_from_partition()` C callback the same way libavb would.
    fn call_read_from_partition(
        ops: &mut TestOps,
        partition: &str,
        offset: i64,
        num_bytes: usize,
        buffer: &mut [u8],
        out_num_read: &mut usize,
    ) -> AvbIOResult {
        let mut user_data = UserData(ops);
        // SAFETY: `user_data` remains in place and unmodified while `avb_ops` exists.
        let mut avb_ops = unsafe { user_data.create_avb_ops() };
        let part_name = CString::new(partition).unwrap();

        // SAFETY: we've properly created and initialized all the raw pointers being passed into
        // this C function.
        unsafe {
            avb_ops.read_from_partition.unwrap()(
                &mut avb_ops as *mut AvbOps,
                part_name.as_ptr(),
                offset,
                num_bytes,
                buffer.as_mut_ptr() as *mut c_void,
                out_num_read as *mut usize,
            )
        }
    }

    // Calls the `get_preloaded_partition()` C callback the same way libavb would.
    fn call_get_preloaded_partition<'a, 'b>(
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
        // SAFETY: `user_data` remains in place and unmodified while `avb_ops` exists.
        let mut avb_ops = unsafe { user_data.create_avb_ops() };
        let part_name = CString::new(partition).unwrap();
        let mut out_ptr: *mut u8 = ptr::null_mut();

        // SAFETY:
        // * We've properly created and initialized all the raw pointers being passed in
        // * We've set up lifetimes such that the `TestOps` which owns the data must outlive
        //   `out_buffer` which wraps the data.
        let result = unsafe {
            avb_ops.get_preloaded_partition.unwrap()(
                &mut avb_ops as *mut AvbOps,
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
        *out_buffer =
            unsafe { buffer_to_slice_mut(out_ptr, *out_num_bytes_preloaded, ops) }.unwrap();
        result
    }

    #[test]
    fn test_read_from_partition() {
        let mut ops = TestOps {
            partitions: HashMap::from([("foo", vec![1u8, 2u8, 3u8, 4u8])]),
            preloaded: HashMap::default(),
        };

        let mut buffer: [u8; 8] = [0; 8];
        let mut bytes_read: usize = 0;
        let result = call_read_from_partition(&mut ops, "foo", 0, 4, &mut buffer, &mut bytes_read);

        assert_eq!(result, AvbIOResult::AVB_IO_RESULT_OK);
        assert_eq!(bytes_read, 4);
        assert_eq!(buffer, [1, 2, 3, 4, 0, 0, 0, 0]);
    }

    #[test]
    fn test_read_from_partition_with_offset() {
        let mut ops = TestOps {
            partitions: HashMap::from([("foo", vec![1u8, 2u8, 3u8, 4u8])]),
            preloaded: HashMap::default(),
        };

        let mut buffer: [u8; 8] = [0; 8];
        let mut bytes_read: usize = 0;
        let result = call_read_from_partition(&mut ops, "foo", 1, 2, &mut buffer, &mut bytes_read);

        assert_eq!(result, AvbIOResult::AVB_IO_RESULT_OK);
        assert_eq!(bytes_read, 2);
        assert_eq!(buffer, [2, 3, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn test_read_from_partition_negative_offset() {
        let mut ops = TestOps {
            partitions: HashMap::from([("foo", vec![1u8, 2u8, 3u8, 4u8])]),
            preloaded: HashMap::default(),
        };

        let mut buffer: [u8; 8] = [0; 8];
        let mut bytes_read: usize = 0;
        let result = call_read_from_partition(&mut ops, "foo", -2, 2, &mut buffer, &mut bytes_read);

        assert_eq!(result, AvbIOResult::AVB_IO_RESULT_OK);
        assert_eq!(bytes_read, 2);
        assert_eq!(buffer, [3, 4, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn test_read_from_partition_truncate() {
        let mut ops = TestOps {
            partitions: HashMap::from([("foo", vec![1u8, 2u8, 3u8, 4u8])]),
            preloaded: HashMap::default(),
        };

        let mut buffer: [u8; 8] = [0; 8];
        let mut bytes_read: usize = 0;
        let result = call_read_from_partition(&mut ops, "foo", 0, 8, &mut buffer, &mut bytes_read);

        assert_eq!(result, AvbIOResult::AVB_IO_RESULT_OK);
        assert_eq!(bytes_read, 4);
        assert_eq!(buffer, [1, 2, 3, 4, 0, 0, 0, 0]);
    }

    #[test]
    fn test_read_from_partition_unknown() {
        let mut ops = TestOps {
            partitions: HashMap::from([("foo", vec![1u8, 2u8, 3u8, 4u8])]),
            preloaded: HashMap::default(),
        };

        let mut buffer: [u8; 8] = [0; 8];
        let mut bytes_read: usize = 10;
        let result = call_read_from_partition(&mut ops, "bar", 0, 8, &mut buffer, &mut bytes_read);

        assert_eq!(result, AvbIOResult::AVB_IO_RESULT_ERROR_NO_SUCH_PARTITION);
        assert_eq!(bytes_read, 0);
        assert_eq!(buffer, [0; 8]);
    }

    #[test]
    fn test_get_preloaded_partition() {
        let mut ops = TestOps {
            partitions: HashMap::default(),
            preloaded: HashMap::from([("foo_preload", vec![1u8, 2u8, 3u8, 4u8])]),
        };

        let mut contents: &mut [u8] = &mut [];
        let mut size: usize = 0;
        let result =
            call_get_preloaded_partition(&mut ops, "foo_preload", 4, &mut contents, &mut size);

        assert_eq!(result, AvbIOResult::AVB_IO_RESULT_OK);
        assert_eq!(size, 4);
        assert_eq!(contents, [1, 2, 3, 4]);
    }

    #[test]
    fn test_get_preloaded_partition_truncate() {
        let mut ops = TestOps {
            partitions: HashMap::default(),
            preloaded: HashMap::from([("foo_preload", vec![1u8, 2u8, 3u8, 4u8])]),
        };

        let mut contents: &mut [u8] = &mut [];
        let mut size: usize = 0;
        let result =
            call_get_preloaded_partition(&mut ops, "foo_preload", 2, &mut contents, &mut size);

        assert_eq!(result, AvbIOResult::AVB_IO_RESULT_OK);
        assert_eq!(size, 2);
        assert_eq!(contents, [1, 2]);
    }

    #[test]
    fn test_get_preloaded_partition_unknown() {
        let mut ops = TestOps {
            partitions: HashMap::default(),
            preloaded: HashMap::from([("foo_preload", vec![1u8, 2u8, 3u8, 4u8])]),
        };

        let mut contents: &mut [u8] = &mut [];
        let mut size: usize = 10;
        let result = call_get_preloaded_partition(&mut ops, "bar", 4, &mut contents, &mut size);

        assert_eq!(result, AvbIOResult::AVB_IO_RESULT_ERROR_NO_SUCH_PARTITION);
        assert_eq!(size, 0);
        assert_eq!(contents, []);
    }
}
