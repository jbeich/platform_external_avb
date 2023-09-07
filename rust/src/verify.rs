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

extern crate alloc;

use crate::{error::result_to_io_enum, IoError};
use avb_bindgen::{AvbIOResult, AvbOps};
use core::{
    cmp::min,
    ffi::{c_char, c_void, CStr},
    marker::PhantomData,
    ptr, slice,
};
#[cfg(feature = "uuid")]
use uuid::Uuid;

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

    /// Reads the rollback index at the given location.
    ///
    /// # Arguments
    /// * `rollback_index_location`: the rollback location.
    ///
    /// # Returns
    /// The rollback index at this location or `IoError` on error.
    fn read_rollback_index(&mut self, rollback_index_location: usize) -> Result<u64>;

    /// Writes the rollback index at the given location.
    ///
    /// This API is never actually used by libavb; the purpose of having it here is to group it
    /// with `read_rollback_index()` and indicate to the implementation that it is responsible
    /// for providing this functionality. However, it's up to the implementation to call this
    /// function at the proper time after verification, which is a device-specific decision that
    /// depends on things like the A/B strategy. See the libavb documentation for more information.
    ///
    /// # Arguments
    /// * `rollback_index_location`: the rollback location.
    /// * `index`: the rollback index to write.
    ///
    /// # Returns
    /// Unit on success or `IoError` on error.
    fn write_rollback_index(&mut self, rollback_index_location: usize, index: u64) -> Result<()>;

    /// Returns the device unlock state.
    ///
    /// # Returns
    /// True if the device is unlocked, false if locked, `IoError` on error.
    fn read_is_device_unlocked(&mut self) -> Result<bool>;

    /// Returns the GUID of the requested partition.
    ///
    /// This is only necessary if the kernel commandline requires GUID substitution, and is omitted
    /// from the library by default to avoid unnecessary dependencies. To implement:
    /// 1. Enable the `uuid` feature during compilation
    /// 2. Provide the [`uuid` crate](https://docs.rs/uuid/latest/uuid/) dependency
    ///
    /// # Arguments
    /// * `partition`: partition name.
    ///
    /// # Returns
    /// The partition GUID or `IoError` on error.
    #[cfg(feature = "uuid")]
    fn get_unique_guid_for_partition(&mut self, partition: &CStr) -> Result<Uuid>;

    /// Returns the size of the requested partition.
    ///
    /// # Arguments
    /// * `partition`: partition name.
    ///
    /// # Returns
    /// The partition size in bytes or `IoError` on error.
    fn get_size_of_partition(&mut self, partition: &CStr) -> Result<u64>;

    /// Reads the requested persistent value.
    ///
    /// This is only necessary if using persistent digests or the "managed restart and EIO"
    /// hashtree verification mode; if verification is not using these features, this function will
    /// never be called.
    ///
    /// # Arguments
    /// * `name`: persistent value name.
    /// * `value`: buffer to read persistent value into; if too small to hold the persistent value,
    ///            `IoError::InsufficientSpace` should be returned and this function will be called
    ///            again with an appropriately-sized buffer. This may be an empty slice if the
    ///            caller only wants to query the persistent value size.
    ///
    /// # Returns
    /// * The number of bytes written into `value` on success.
    /// * `IoError::NoSuchValue` if `name` is not a known persistent value.
    /// * `IoError::InsufficientSpace` with the required size if the `value` buffer is too small.
    /// * Any other `IoError` on failure.
    fn read_persistent_value(&mut self, name: &CStr, value: &mut [u8]) -> Result<usize>;

    /// Writes the requested persistent value.
    ///
    /// This is only necessary if using persistent digests or the "managed restart and EIO"
    /// hashtree verification mode; if verification is not using these features, this function will
    /// never be called.
    ///
    /// # Arguments
    /// * `name`: persistent value name.
    /// * `value`: bytes to write as the new value.
    ///
    /// # Returns
    /// * Unit on success.
    /// * `IoError::NoSuchValue` if `name` is not a supported persistent value.
    /// * `IoError::InvalidValueSize` if `value` is too large to save as a persistent value.
    /// * Any other `IoError` on failure.
    fn write_persistent_value(&mut self, name: &CStr, value: &[u8]) -> Result<()>;

    /// Erases the requested persistent value.
    ///
    /// This is only necessary if using persistent digests or the "managed restart and EIO"
    /// hashtree verification mode; if verification is not using these features, this function will
    /// never be called.
    ///
    /// If the requested persistent value is already erased, this function is a no-op and should
    /// return `Ok(())`.
    ///
    /// # Arguments
    /// * `name`: persistent value name.
    ///
    /// # Returns
    /// * Unit on success.
    /// * `IoError::NoSuchValue` if `name` is not a supported persistent value.
    /// * Any other `IoError` on failure.
    fn erase_persistent_value(&mut self, name: &CStr) -> Result<()>;
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
///                                  `ScopedAvbOps` makes
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

/// Wraps the C `AvbOps` struct with lifetime information for the compiler.
struct ScopedAvbOps<'a> {
    /// `AvbOps` holds a raw pointer to `UserData` with no lifetime information.
    avb_ops: AvbOps,
    /// This provides the necessary lifetime information so the compiler can make sure that
    /// the `UserData` stays alive at least as long as we do.
    _user_data: PhantomData<UserData<'a>>,
}

impl<'a> ScopedAvbOps<'a> {
    fn new(user_data: &'a mut UserData<'a>) -> Self {
        Self {
            avb_ops: AvbOps {
                // Rust won't transitively cast so we need to cast twice manually, but the compiler
                // is smart enough to deduce the types we need.
                user_data: user_data as *mut _ as *mut _,
                ab_ops: ptr::null_mut(),  // Deprecated, no need to support.
                atx_ops: ptr::null_mut(), // TODO: support optional ATX.
                read_from_partition: Some(read_from_partition),
                get_preloaded_partition: Some(get_preloaded_partition),
                write_to_partition: None, // Not needed, only used for deprecated A/B.
                validate_vbmeta_public_key: Some(validate_vbmeta_public_key),
                read_rollback_index: Some(read_rollback_index),
                write_rollback_index: Some(write_rollback_index),
                read_is_device_unlocked: Some(read_is_device_unlocked),
                get_unique_guid_for_partition: Some(get_unique_guid_for_partition),
                get_size_of_partition: Some(get_size_of_partition),
                read_persistent_value: Some(read_persistent_value),
                write_persistent_value: Some(write_persistent_value),
                // TODO: add callback wrappers for the remaining API.
                validate_public_key_for_partition: None,
            },
            _user_data: PhantomData,
        }
    }
}

impl<'a> AsMut<AvbOps> for ScopedAvbOps<'a> {
    fn as_mut(&mut self) -> &mut AvbOps {
        &mut self.avb_ops
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
/// Only call this function on an `AvbOps` created via `ScopedAvbOps`.
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
/// * `ops` must have been created via `ScopedAvbOps`.
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
    // * we only use `ops` objects created via `ScopedAvbOps` as required.
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
/// * `ops` must have been created via `ScopedAvbOps`.
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
    // * we only use `ops` objects created via `ScopedAvbOps` as required.
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
/// * `ops` must have been created via `ScopedAvbOps`.
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
    // * we only use `ops` objects created via `ScopedAvbOps` as required.
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

/// Wraps a callback to convert the given `Result<>` to raw `AvbIOResult` for libavb.
///
/// See corresponding `try_*` function docs.
unsafe extern "C" fn read_rollback_index(
    ops: *mut AvbOps,
    rollback_index_location: usize,
    out_rollback_index: *mut u64,
) -> AvbIOResult {
    result_to_io_enum(try_read_rollback_index(
        ops,
        rollback_index_location,
        out_rollback_index,
    ))
}

/// Bounces the C callback into the user-provided Rust implementation.
///
/// # Safety
/// * `ops` must have been created via `ScopedAvbOps`.
/// * `out_rollback_index` must adhere to the requirements of `ptr::write()`.
unsafe fn try_read_rollback_index(
    ops: *mut AvbOps,
    rollback_index_location: usize,
    out_rollback_index: *mut u64,
) -> Result<()> {
    check_nonnull(out_rollback_index)?;

    // Initialize the output variables first in case something fails.
    // SAFETY:
    // * we've checked that the pointer is non-NULL.
    // * libavb gives us a properly-allocated `out_rollback_index`.
    unsafe { ptr::write(out_rollback_index, 0) };

    // SAFETY:
    // * we only use `ops` objects created via `ScopedAvbOps` as required.
    // * `ops` is only extracted once and is dropped at the end of the callback.
    let ops = unsafe { as_ops(ops) }?;
    let index = ops.read_rollback_index(rollback_index_location)?;

    // SAFETY:
    // * we've checked that the pointer is non-NULL.
    // * libavb gives us a properly-allocated `out_rollback_index`.
    unsafe { ptr::write(out_rollback_index, index) };
    Ok(())
}

/// Wraps a callback to convert the given `Result<>` to raw `AvbIOResult` for libavb.
///
/// See corresponding `try_*` function docs.
unsafe extern "C" fn write_rollback_index(
    ops: *mut AvbOps,
    rollback_index_location: usize,
    rollback_index: u64,
) -> AvbIOResult {
    result_to_io_enum(try_write_rollback_index(
        ops,
        rollback_index_location,
        rollback_index,
    ))
}

/// Bounces the C callback into the user-provided Rust implementation.
///
/// # Safety
/// * `ops` must have been created via `ScopedAvbOps`.
unsafe fn try_write_rollback_index(
    ops: *mut AvbOps,
    rollback_index_location: usize,
    rollback_index: u64,
) -> Result<()> {
    // SAFETY:
    // * we only use `ops` objects created via `ScopedAvbOps` as required.
    // * `ops` is only extracted once and is dropped at the end of the callback.
    let ops = unsafe { as_ops(ops) }?;
    ops.write_rollback_index(rollback_index_location, rollback_index)
}

/// Wraps a callback to convert the given `Result<>` to raw `AvbIOResult` for libavb.
///
/// See corresponding `try_*` function docs.
unsafe extern "C" fn read_is_device_unlocked(
    ops: *mut AvbOps,
    out_is_unlocked: *mut bool,
) -> AvbIOResult {
    result_to_io_enum(try_read_is_device_unlocked(ops, out_is_unlocked))
}

/// Bounces the C callback into the user-provided Rust implementation.
///
/// # Safety
/// * `ops` must have been created via `ScopedAvbOps`.
/// * `out_is_unlocked` must adhere to the requirements of `ptr::write()`.
unsafe fn try_read_is_device_unlocked(ops: *mut AvbOps, out_is_unlocked: *mut bool) -> Result<()> {
    check_nonnull(out_is_unlocked)?;

    // Initialize the output variables first in case something fails.
    // SAFETY:
    // * we've checked that the pointer is non-NULL.
    // * libavb gives us a properly-allocated `out_is_unlocked`.
    unsafe { ptr::write(out_is_unlocked, false) };

    // SAFETY:
    // * we only use `ops` objects created via `ScopedAvbOps` as required.
    // * `ops` is only extracted once and is dropped at the end of the callback.
    let ops = unsafe { as_ops(ops) }?;
    let unlocked = ops.read_is_device_unlocked()?;

    // SAFETY:
    // * we've checked that the pointer is non-NULL.
    // * libavb gives us a properly-allocated `out_is_unlocked`.
    unsafe { ptr::write(out_is_unlocked, unlocked) };
    Ok(())
}

/// Wraps a callback to convert the given `Result<>` to raw `AvbIOResult` for libavb.
///
/// See corresponding `try_*` function docs.
#[cfg(feature = "uuid")]
unsafe extern "C" fn get_unique_guid_for_partition(
    ops: *mut AvbOps,
    partition: *const c_char,
    guid_buf: *mut c_char,
    guid_buf_size: usize,
) -> AvbIOResult {
    result_to_io_enum(try_get_unique_guid_for_partition(
        ops,
        partition,
        guid_buf,
        guid_buf_size,
    ))
}

/// When compiled without the `uuid` feature this callback is not used, just return error.
#[cfg(not(feature = "uuid"))]
unsafe extern "C" fn get_unique_guid_for_partition(
    ops: *mut AvbOps,
    partition: *const c_char,
    guid_buf: *mut c_char,
    guid_buf_size: usize,
) -> AvbIOResult {
    AvbIOResult::AVB_IO_RESULT_ERROR_NO_SUCH_PARTITION
}

/// Bounces the C callback into the user-provided Rust implementation.
///
/// # Safety
/// * `ops` must have been created via `ScopedAvbOps`.
/// * `partition` must adhere to the requirements of `CStr::from_ptr()`.
/// * `guid_buf` must adhere to the requirements of `slice::from_raw_parts_mut()`.
#[cfg(feature = "uuid")]
unsafe fn try_get_unique_guid_for_partition(
    ops: *mut AvbOps,
    partition: *const c_char,
    guid_buf: *mut c_char,
    guid_buf_size: usize,
) -> Result<()> {
    check_nonnull(partition)?;
    check_nonnull(guid_buf)?;

    // SAFETY:
    // * we only use `ops` objects created via `ScopedAvbOps` as required.
    // * `ops` is only extracted once and is dropped at the end of the callback.
    let ops = unsafe { as_ops(ops) }?;
    // SAFETY:
    // * we've checked that the pointer is non-NULL.
    // * libavb gives us a properly-allocated and nul-terminated `partition`.
    // * the string contents are not modified while the returned `&CStr` exists.
    // * the returned `&CStr` is not held past the scope of this callback.
    let partition = unsafe { CStr::from_ptr(partition) };
    let guid = ops.get_unique_guid_for_partition(partition)?;

    // Write the UUID string to a uuid buffer which is guaranteed to be large enough, then use
    // `CString` to apply nul-termination.
    // This does allocate memory, but it's short-lived and discarded as soon as we copy the
    // properly-terminated string back to the buffer.
    let mut encode_buffer = uuid::Uuid::encode_buffer();
    let guid_str = guid.as_hyphenated().encode_lower(&mut encode_buffer);
    let guid_cstring = alloc::ffi::CString::new(guid_str.as_bytes()).or(Err(IoError::Io))?;
    let guid_bytes = guid_cstring.to_bytes_with_nul();

    if guid_buf_size < guid_bytes.len() {
        // This would indicate some internal error - the uuid library needs more
        // space to print the UUID string than libavb provided.
        return Err(IoError::Oom);
    }

    // SAFETY:
    // * we've checked that the pointer is non-NULL.
    // * libavb gives us a properly-allocated `guid_buf` with size `guid_buf_size`.
    // * we only access the contents via the returned slice.
    // * the returned slice is not held past the scope of this callback.
    let buffer = unsafe { slice::from_raw_parts_mut(guid_buf as *mut u8, guid_buf_size) };
    buffer[..guid_bytes.len()].copy_from_slice(guid_bytes);
    Ok(())
}

/// Wraps a callback to convert the given `Result<>` to raw `AvbIOResult` for libavb.
///
/// See corresponding `try_*` function docs.
unsafe extern "C" fn get_size_of_partition(
    ops: *mut AvbOps,
    partition: *const c_char,
    out_size_num_bytes: *mut u64,
) -> AvbIOResult {
    result_to_io_enum(try_get_size_of_partition(
        ops,
        partition,
        out_size_num_bytes,
    ))
}

/// Bounces the C callback into the user-provided Rust implementation.
///
/// # Safety
/// * `ops` must have been created via `ScopedAvbOps`.
/// * `partition` must adhere to the requirements of `CStr::from_ptr()`.
/// * `out_size_num_bytes` must adhere to the requirements of `ptr::write()`.
unsafe fn try_get_size_of_partition(
    ops: *mut AvbOps,
    partition: *const c_char,
    out_size_num_bytes: *mut u64,
) -> Result<()> {
    check_nonnull(partition)?;
    check_nonnull(out_size_num_bytes)?;

    // Initialize the output variables first in case something fails.
    // SAFETY:
    // * we've checked that the pointer is non-NULL.
    // * libavb gives us a properly-allocated `out_size_num_bytes`.
    unsafe { ptr::write(out_size_num_bytes, 0) };

    // SAFETY:
    // * we only use `ops` objects created via `ScopedAvbOps` as required.
    // * `ops` is only extracted once and is dropped at the end of the callback.
    let ops = unsafe { as_ops(ops) }?;
    // SAFETY:
    // * we've checked that the pointer is non-NULL.
    // * libavb gives us a properly-allocated and nul-terminated `partition`.
    // * the string contents are not modified while the returned `&CStr` exists.
    // * the returned `&CStr` is not held past the scope of this callback.
    let partition = unsafe { CStr::from_ptr(partition) };
    let size = ops.get_size_of_partition(partition)?;

    // SAFETY:
    // * we've checked that the pointer is non-NULL.
    // * libavb gives us a properly-allocated `out_size_num_bytes`.
    unsafe { ptr::write(out_size_num_bytes, size) };
    Ok(())
}

/// Wraps a callback to convert the given `Result<>` to raw `AvbIOResult` for libavb.
///
/// See corresponding `try_*` function docs.
unsafe extern "C" fn read_persistent_value(
    ops: *mut AvbOps,
    name: *const c_char,
    buffer_size: usize,
    out_buffer: *mut u8,
    out_num_bytes_read: *mut usize,
) -> AvbIOResult {
    result_to_io_enum(try_read_persistent_value(
        ops,
        name,
        buffer_size,
        out_buffer,
        out_num_bytes_read,
    ))
}

/// Bounces the C callback into the user-provided Rust implementation.
///
/// # Safety
/// * `ops` must have been created via `ScopedAvbOps`.
/// * `name` must adhere to the requirements of `CStr::from_ptr()`.
/// * `out_buffer` must adhere to the requirements of `slice::from_raw_parts_mut()`.
/// * `out_num_bytes_read` must adhere to the requirements of `ptr::write()`.
unsafe fn try_read_persistent_value(
    ops: *mut AvbOps,
    name: *const c_char,
    buffer_size: usize,
    out_buffer: *mut u8,
    out_num_bytes_read: *mut usize,
) -> Result<()> {
    check_nonnull(name)?;
    check_nonnull(out_num_bytes_read)?;

    // Initialize the output variables first in case something fails.
    // SAFETY:
    // * we've checked that the pointer is non-NULL.
    // * libavb gives us a properly-allocated `out_num_bytes_read`.
    unsafe { ptr::write(out_num_bytes_read, 0) };

    // SAFETY:
    // * we only use `ops` objects created via `ScopedAvbOps` as required.
    // * `ops` is only extracted once and is dropped at the end of the callback.
    let ops = unsafe { as_ops(ops) }?;
    // SAFETY:
    // * we've checked that the pointer is non-NULL.
    // * libavb gives us a properly-allocated and nul-terminated `name`.
    // * the string contents are not modified while the returned `&CStr` exists.
    // * the returned `&CStr` is not held past the scope of this callback.
    let name = unsafe { CStr::from_ptr(name) };
    let mut empty: [u8; 0] = [];
    let value = match out_buffer.is_null() {
        // NULL buffer => empty slice, used to just query the value size.
        true => &mut empty,
        false => {
            // SAFETY:
            // * we've checked that the pointer is non-NULL.
            // * libavb gives us a properly-allocated `out_buffer` with size `buffer_size`.
            // * we only access the contents via the returned slice.
            // * the returned slice is not held past the scope of this callback.
            unsafe { slice::from_raw_parts_mut(out_buffer as *mut u8, buffer_size) }
        }
    };

    let result = ops.read_persistent_value(name, value);
    // On success or insufficient space we need to write the property size back.
    if let Ok(size) | Err(IoError::InsufficientSpace(size)) = result {
        // SAFETY:
        // * we've checked that the pointer is non-NULL.
        // * libavb gives us a properly-allocated `out_num_bytes_read`.
        unsafe { ptr::write(out_num_bytes_read, size) };
    };
    // We've written the size back and can drop it now.
    result.map(|_| ())
}

/// Wraps a callback to convert the given `Result<>` to raw `AvbIOResult` for libavb.
///
/// See corresponding `try_*` function docs.
unsafe extern "C" fn write_persistent_value(
    ops: *mut AvbOps,
    name: *const c_char,
    value_size: usize,
    value: *const u8,
) -> AvbIOResult {
    result_to_io_enum(try_write_persistent_value(ops, name, value_size, value))
}

/// Bounces the C callback into the user-provided Rust implementation.
///
/// # Safety
/// * `ops` must have been created via `ScopedAvbOps`.
/// * `name` must adhere to the requirements of `CStr::from_ptr()`.
/// * `out_buffer` must adhere to the requirements of `slice::from_raw_parts()`.
unsafe fn try_write_persistent_value(
    ops: *mut AvbOps,
    name: *const c_char,
    value_size: usize,
    value: *const u8,
) -> Result<()> {
    check_nonnull(name)?;

    // SAFETY:
    // * we only use `ops` objects created via `ScopedAvbOps` as required.
    // * `ops` is only extracted once and is dropped at the end of the callback.
    let ops = unsafe { as_ops(ops) }?;
    // SAFETY:
    // * we've checked that the pointer is non-NULL.
    // * libavb gives us a properly-allocated and nul-terminated `name`.
    // * the string contents are not modified while the returned `&CStr` exists.
    // * the returned `&CStr` is not held past the scope of this callback.
    let name = unsafe { CStr::from_ptr(name) };

    if value_size == 0 {
        ops.erase_persistent_value(name)
    } else {
        check_nonnull(value)?;
        // SAFETY:
        // * we've checked that the pointer is non-NULL.
        // * libavb gives us a properly-allocated `value` with size `value_size`.
        // * we only access the contents via the returned slice.
        // * the returned slice is not held past the scope of this callback.
        let value = unsafe { slice::from_raw_parts(value, value_size) };
        ops.write_persistent_value(name, value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::HashMap;
    use std::ffi::CString;
    #[cfg(feature = "uuid")]
    use uuid::uuid;

    /// Length of a UUID C-string representation including hyphens and a null-terminator.
    #[cfg(feature = "uuid")]
    const UUID_CSTRING_LENGTH: usize = uuid::fmt::Hyphenated::LENGTH + 1;

    /// Represents a single fake partition.
    #[derive(Default)]
    struct FakePartition {
        contents: Vec<u8>, // Partition contents
        preloaded: bool,   // Whether it should report as preloaded or not
        #[cfg(feature = "uuid")]
        uuid: Uuid, // Partition UUID
    }

    /// Ops implementation for testing.
    ///
    /// In addition to being used to exercise individual callback wrappers, this will be used for
    /// full verification tests so behavior needs to be correct.
    struct TestOps {
        /// Partitions to provide to libavb callbacks.
        partitions: HashMap<&'static str, FakePartition>,
        /// Vbmeta public keys as a map of {(key, metadata): trusted}. Querying unknown keys will
        /// return `IoError::Io`.
        vbmeta_keys: HashMap<(&'static [u8], Option<&'static [u8]>), bool>,
        /// Rollback indices. Accessing unknown locations will return `IoError::Io`.
        rollbacks: HashMap<usize, u64>,
        /// Unlock state. Set an error to simulate IoError during access.
        unlock_state: Result<bool>,
        /// Persistent named values. Set an error to simulate `IoError` during access. Writing
        /// a non-existent persistent value will create it; to simulate `NoSuchValue` instead,
        /// create an entry with `Err(IoError::NoSuchValue)` as the value.
        persistent_values: HashMap<String, Result<Vec<u8>>>,
    }

    impl TestOps {
        /// Adds a partition with the given contents.
        ///
        /// Reduces boilerplate a bit by taking in a raw array and returning a &mut so tests can
        /// do something like this:
        ///
        /// ```
        /// test_ops.add_partition("foo", [1, 2, 3, 4]);
        /// test_ops.add_partition("bar", [0, 0]).preloaded = true;
        /// ```
        fn add_partition<const N: usize>(
            &mut self,
            name: &'static str,
            contents: [u8; N],
        ) -> &mut FakePartition {
            self.partitions.insert(
                name,
                FakePartition {
                    contents: contents.into(),
                    ..Default::default()
                },
            );
            self.partitions.get_mut(name).unwrap()
        }

        /// Adds a persistent value with the given state.
        ///
        /// Reduces boilerplate by allowing array input:
        ///
        /// ```
        /// test_ops.add_persistent_value("foo", Ok(b"contents"));
        /// test_ops.add_persistent_value("bar", Err(IoError::NoSuchValue));
        /// ```
        fn add_persistent_value(&mut self, name: &str, contents: Result<&[u8]>) {
            self.persistent_values
                .insert(name.into(), contents.map(|b| b.into()));
        }
    }

    impl Default for TestOps {
        fn default() -> Self {
            Self {
                partitions: HashMap::new(),
                vbmeta_keys: HashMap::new(),
                rollbacks: HashMap::new(),
                unlock_state: Err(IoError::Io),
                persistent_values: HashMap::new(),
            }
        }
    }

    impl Ops for TestOps {
        fn read_from_partition(
            &mut self,
            partition: &CStr,
            offset: i64,
            buffer: &mut [u8],
        ) -> Result<usize> {
            let partition = self
                .partitions
                .get(partition.to_str()?)
                .ok_or(IoError::NoSuchPartition)?;

            // We should never be trying to read a preloaded partition from disk since we already
            // have it available in memory.
            assert!(!partition.preloaded);

            let contents = &partition.contents;

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
            match self.partitions.get(partition.to_str()?) {
                Some(FakePartition {
                    contents,
                    preloaded: true,
                    ..
                }) => Ok(&contents[..]),
                _ => Err(IoError::NotImplemented),
            }
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

        fn read_rollback_index(&mut self, location: usize) -> Result<u64> {
            self.rollbacks.get(&location).ok_or(IoError::Io).copied()
        }

        fn write_rollback_index(&mut self, location: usize, index: u64) -> Result<()> {
            *(self.rollbacks.get_mut(&location).ok_or(IoError::Io)?) = index;
            Ok(())
        }

        fn read_is_device_unlocked(&mut self) -> Result<bool> {
            self.unlock_state.clone()
        }

        #[cfg(feature = "uuid")]
        fn get_unique_guid_for_partition(&mut self, partition: &CStr) -> Result<Uuid> {
            self.partitions
                .get(partition.to_str()?)
                .map(|p| p.uuid)
                .ok_or(IoError::NoSuchPartition)
        }

        fn get_size_of_partition(&mut self, partition: &CStr) -> Result<u64> {
            self.partitions
                .get(partition.to_str()?)
                .map(|p| u64::try_from(p.contents.len()).unwrap())
                .ok_or(IoError::NoSuchPartition)
        }

        fn read_persistent_value(&mut self, name: &CStr, value: &mut [u8]) -> Result<usize> {
            match self
                .persistent_values
                .get(name.to_str()?)
                .ok_or(IoError::NoSuchValue)?
            {
                // If we were given enough space, write the value contents.
                Ok(contents) if contents.len() <= value.len() => {
                    value[..contents.len()].clone_from_slice(contents);
                    Ok(contents.len())
                }
                // Not enough space, tell the caller how much we need.
                Ok(contents) => Err(IoError::InsufficientSpace(contents.len())),
                // Simulated error, return it.
                Err(e) => Err(e.clone()),
            }
        }

        fn write_persistent_value(&mut self, name: &CStr, value: &[u8]) -> Result<()> {
            let name = name.to_str()?;

            // If the test requested a simulated error on this value, return it.
            if let Some(Err(e)) = self.persistent_values.get(name) {
                return Err(e.clone());
            }

            self.persistent_values
                .insert(name.to_string(), Ok(value.to_vec()));
            Ok(())
        }

        fn erase_persistent_value(&mut self, name: &CStr) -> Result<()> {
            let name = name.to_str()?;

            // If the test requested a simulated error on this value, return it.
            if let Some(Err(e)) = self.persistent_values.get(name) {
                return Err(e.clone());
            }

            self.persistent_values.remove(name);
            Ok(())
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
        let mut scoped_ops = ScopedAvbOps::new(&mut user_data);
        let avb_ops = scoped_ops.as_mut();
        let part_name = CString::new(partition).unwrap();

        // SAFETY: we've properly created and initialized all the raw pointers being passed into
        // this C function.
        unsafe {
            avb_ops.read_from_partition.unwrap()(
                avb_ops,
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
        let mut scoped_ops = ScopedAvbOps::new(&mut user_data);
        let avb_ops = scoped_ops.as_mut();
        let part_name = CString::new(partition).unwrap();
        let mut out_ptr: *mut u8 = ptr::null_mut();

        // SAFETY:
        // * We've properly created and initialized all the raw pointers being passed in
        // * We've set up lifetimes such that the `TestOps` which owns the data will outlive
        //   `out_buffer` which wraps the data.
        let result = unsafe {
            avb_ops.get_preloaded_partition.unwrap()(
                avb_ops,
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
        let mut scoped_ops = ScopedAvbOps::new(&mut user_data);
        let avb_ops = scoped_ops.as_mut();
        let (metadata_ptr, metadata_size) =
            public_key_metadata.map_or((ptr::null(), 0), |m| (m.as_ptr(), m.len()));

        // SAFETY: we've properly created and initialized all the raw pointers being passed in.
        unsafe {
            avb_ops.validate_vbmeta_public_key.unwrap()(
                avb_ops,
                public_key.as_ptr(),
                public_key.len(),
                metadata_ptr,
                metadata_size,
                out_is_trusted,
            )
        }
    }

    /// Calls the `read_rollback_index()` C callback the same way libavb would.
    fn call_read_rollback_index(
        ops: &mut impl Ops,
        rollback_index_location: usize,
        out_index: &mut u64,
    ) -> AvbIOResult {
        let mut user_data = UserData(ops);
        let mut scoped_ops = ScopedAvbOps::new(&mut user_data);
        let avb_ops = scoped_ops.as_mut();

        // SAFETY: we've properly created and initialized all the raw pointers being passed in.
        unsafe { avb_ops.read_rollback_index.unwrap()(avb_ops, rollback_index_location, out_index) }
    }

    /// Calls the `write_rollback_index()` C callback the same way libavb would.
    fn call_write_rollback_index(
        ops: &mut impl Ops,
        rollback_index_location: usize,
        index: u64,
    ) -> AvbIOResult {
        let mut user_data = UserData(ops);
        let mut scoped_ops = ScopedAvbOps::new(&mut user_data);
        let avb_ops = scoped_ops.as_mut();

        // SAFETY: we've properly created and initialized all the raw pointers being passed in.
        unsafe { avb_ops.write_rollback_index.unwrap()(avb_ops, rollback_index_location, index) }
    }

    /// Calls the `read_is_device_unlocked()` C callback the same way libavb would.
    fn call_read_is_device_unlocked(ops: &mut impl Ops, out_is_unlocked: &mut bool) -> AvbIOResult {
        let mut user_data = UserData(ops);
        let mut scoped_ops = ScopedAvbOps::new(&mut user_data);
        let avb_ops = scoped_ops.as_mut();

        // SAFETY: we've properly created and initialized all the raw pointers being passed in.
        unsafe { avb_ops.read_is_device_unlocked.unwrap()(avb_ops, out_is_unlocked) }
    }

    /// Calls the `get_unique_guid_for_partition()` C callback the same way libavb would.
    fn call_get_unique_guid_for_partition(
        ops: &mut impl Ops,
        partition: &str,
        out_guid_str: &mut [u8],
    ) -> AvbIOResult {
        let mut user_data = UserData(ops);
        let mut scoped_ops = ScopedAvbOps::new(&mut user_data);
        let avb_ops = scoped_ops.as_mut();
        let part_name = CString::new(partition).unwrap();

        // SAFETY: we've properly created and initialized all the raw pointers being passed in.
        unsafe {
            avb_ops.get_unique_guid_for_partition.unwrap()(
                avb_ops,
                part_name.as_ptr(),
                out_guid_str.as_mut_ptr() as *mut _,
                out_guid_str.len(),
            )
        }
    }

    /// Calls the `get_size_of_partition()` C callback the same way libavb would.
    fn call_get_size_of_partition(
        ops: &mut impl Ops,
        partition: &str,
        out_size: &mut u64,
    ) -> AvbIOResult {
        let mut user_data = UserData(ops);
        let mut scoped_ops = ScopedAvbOps::new(&mut user_data);
        let avb_ops = scoped_ops.as_mut();
        let part_name = CString::new(partition).unwrap();

        // SAFETY: we've properly created and initialized all the raw pointers being passed in.
        unsafe { avb_ops.get_size_of_partition.unwrap()(avb_ops, part_name.as_ptr(), out_size) }
    }

    /// Calls the `read_persistent_value()` C callback the same way libavb would.
    fn call_read_persistent_value(
        ops: &mut impl Ops,
        name: &str,
        out_buffer: Option<&mut [u8]>,
        out_num_bytes_read: &mut usize,
    ) -> AvbIOResult {
        let mut user_data = UserData(ops);
        let mut scoped_ops = ScopedAvbOps::new(&mut user_data);
        let avb_ops = scoped_ops.as_mut();
        let name = CString::new(name).unwrap();
        let (buffer_ptr, buffer_size) =
            out_buffer.map_or((ptr::null_mut(), 0), |b| (b.as_mut_ptr(), b.len()));

        // SAFETY: we've properly created and initialized all the raw pointers being passed in.
        unsafe {
            avb_ops.read_persistent_value.unwrap()(
                avb_ops,
                name.as_ptr(),
                buffer_size,
                buffer_ptr,
                out_num_bytes_read,
            )
        }
    }

    /// Calls the `write_persistent_value()` C callback the same way libavb would.
    fn call_write_persistent_value(
        ops: &mut impl Ops,
        name: &str,
        value: Option<&[u8]>,
    ) -> AvbIOResult {
        let mut user_data = UserData(ops);
        let mut scoped_ops = ScopedAvbOps::new(&mut user_data);
        let avb_ops = scoped_ops.as_mut();
        let name = CString::new(name).unwrap();
        let (value_ptr, value_size) = value.map_or((ptr::null(), 0), |v| (v.as_ptr(), v.len()));

        // SAFETY: we've properly created and initialized all the raw pointers being passed in.
        unsafe {
            avb_ops.write_persistent_value.unwrap()(avb_ops, name.as_ptr(), value_size, value_ptr)
        }
    }

    #[test]
    fn test_read_from_partition() {
        let mut ops = TestOps::default();
        ops.add_partition("foo", [1, 2, 3, 4]);

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
        ops.add_partition("foo", [1, 2, 3, 4]);

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
        ops.add_partition("foo", [1, 2, 3, 4]);

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
        ops.add_partition("foo", [1, 2, 3, 4]);

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
        ops.add_partition("foo", [1, 2, 3, 4]);

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
        ops.add_partition("foo_preload", [1, 2, 3, 4]).preloaded = true;

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
        ops.add_partition("foo_preload", [1, 2, 3, 4]).preloaded = true;

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
        ops.add_partition("foo_preload", [1, 2, 3, 4]).preloaded = true;

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

    #[test]
    fn test_read_rollback_index() {
        let mut ops = TestOps::default();
        ops.rollbacks.insert(10, 20);

        let mut index = 0u64;
        assert_eq!(
            call_read_rollback_index(&mut ops, 10, &mut index),
            AvbIOResult::AVB_IO_RESULT_OK
        );
        assert_eq!(index, 20);
    }

    #[test]
    fn test_read_rollback_index_not_found() {
        let mut ops = TestOps::default();

        let mut index = 30u64;
        assert_eq!(
            call_read_rollback_index(&mut ops, 10, &mut index),
            AvbIOResult::AVB_IO_RESULT_ERROR_IO
        );
        assert_eq!(index, 0);
    }

    #[test]
    fn test_write_rollback_index() {
        let mut ops = TestOps::default();
        ops.rollbacks.insert(10, 20);

        assert_eq!(
            call_write_rollback_index(&mut ops, 10, 30),
            AvbIOResult::AVB_IO_RESULT_OK
        );
        assert_eq!(*ops.rollbacks.get(&10).unwrap(), 30);
    }

    #[test]
    fn test_read_is_device_unlocked_yes() {
        let mut ops = TestOps::default();
        ops.unlock_state = Ok(true);

        let mut unlocked = false;
        assert_eq!(
            call_read_is_device_unlocked(&mut ops, &mut unlocked),
            AvbIOResult::AVB_IO_RESULT_OK
        );
        assert_eq!(unlocked, true);
    }

    #[test]
    fn test_read_is_device_unlocked_no() {
        let mut ops = TestOps::default();
        ops.unlock_state = Ok(false);

        let mut unlocked = true;
        assert_eq!(
            call_read_is_device_unlocked(&mut ops, &mut unlocked),
            AvbIOResult::AVB_IO_RESULT_OK
        );
        assert_eq!(unlocked, false);
    }

    #[test]
    fn test_read_is_device_unlocked_error() {
        let mut ops = TestOps::default();
        ops.unlock_state = Err(IoError::Io);

        let mut unlocked = true;
        assert_eq!(
            call_read_is_device_unlocked(&mut ops, &mut unlocked),
            AvbIOResult::AVB_IO_RESULT_ERROR_IO
        );
        assert_eq!(unlocked, false);
    }

    #[cfg(feature = "uuid")]
    #[test]
    fn test_get_unique_guid_for_partition() {
        let mut ops = TestOps::default();
        ops.add_partition("foo", []).uuid = uuid!("01234567-89ab-cdef-0123-456789abcdef");

        let mut uuid_str = [b'?'; UUID_CSTRING_LENGTH];
        assert_eq!(
            call_get_unique_guid_for_partition(&mut ops, "foo", &mut uuid_str[..]),
            AvbIOResult::AVB_IO_RESULT_OK
        );
        assert_eq!(
            String::from_utf8(uuid_str.into()).unwrap(),
            "01234567-89ab-cdef-0123-456789abcdef\0"
        )
    }

    #[cfg(feature = "uuid")]
    #[test]
    fn test_get_unique_guid_for_partition_unknown() {
        let mut ops = TestOps::default();

        let mut uuid_str = [b'?'; UUID_CSTRING_LENGTH];
        assert_eq!(
            call_get_unique_guid_for_partition(&mut ops, "foo", &mut uuid_str[..]),
            AvbIOResult::AVB_IO_RESULT_ERROR_NO_SUCH_PARTITION
        );
    }

    #[cfg(feature = "uuid")]
    #[test]
    fn test_get_unique_guid_for_partition_undersize_buffer() {
        let mut ops = TestOps::default();
        ops.add_partition("foo", []).uuid = uuid!("01234567-89ab-cdef-0123-456789abcdef");

        let mut uuid_str = [b'?'; UUID_CSTRING_LENGTH - 1];
        assert_eq!(
            call_get_unique_guid_for_partition(&mut ops, "foo", &mut uuid_str[..]),
            AvbIOResult::AVB_IO_RESULT_ERROR_OOM
        );
    }

    #[cfg(not(feature = "uuid"))]
    #[test]
    fn test_get_unique_guid_for_partition_not_implemented() {
        let mut ops = TestOps::default();
        ops.add_partition("foo", []);

        // Without the `uuid` feature enabled, get_unique_guid_for_partition() should
        // unconditionally fail without trying to call any Ops functions.
        let mut uuid_str = [b'?'; 0];
        assert_eq!(
            call_get_unique_guid_for_partition(&mut ops, "foo", &mut uuid_str[..]),
            AvbIOResult::AVB_IO_RESULT_ERROR_NO_SUCH_PARTITION
        );
    }

    #[test]
    fn test_get_size_of_partition() {
        let mut ops = TestOps::default();
        ops.add_partition("foo", [1, 2, 3, 4]);

        let mut size = 0;
        let result = call_get_size_of_partition(&mut ops, "foo", &mut size);

        assert_eq!(result, AvbIOResult::AVB_IO_RESULT_OK);
        assert_eq!(size, 4);
    }

    #[test]
    fn test_get_size_of_partition_unknown() {
        let mut ops = TestOps::default();

        let mut size = 10;
        let result = call_get_size_of_partition(&mut ops, "foo", &mut size);

        assert_eq!(result, AvbIOResult::AVB_IO_RESULT_ERROR_NO_SUCH_PARTITION);
        assert_eq!(size, 0);
    }

    #[test]
    fn test_read_persistent_value() {
        let mut ops = TestOps::default();
        ops.add_persistent_value("foo", Ok(b"1234"));

        let mut size = 0;
        let mut buffer = [b'.'; 8];
        let result = call_read_persistent_value(&mut ops, "foo", Some(&mut buffer), &mut size);

        assert_eq!(result, AvbIOResult::AVB_IO_RESULT_OK);
        assert_eq!(size, 4);
        assert_eq!(&buffer[..], b"1234....");
    }

    #[test]
    fn test_read_persistent_value_buffer_too_small() {
        let mut ops = TestOps::default();
        ops.add_persistent_value("foo", Ok(b"1234"));

        let mut size = 0;
        let mut buffer = [b'.'; 2];
        let result = call_read_persistent_value(&mut ops, "foo", Some(&mut buffer), &mut size);

        assert_eq!(result, AvbIOResult::AVB_IO_RESULT_ERROR_INSUFFICIENT_SPACE);
        assert_eq!(size, 4);
        assert_eq!(&buffer[..], b"..");
    }

    #[test]
    fn test_read_persistent_value_buffer_null() {
        let mut ops = TestOps::default();
        ops.add_persistent_value("foo", Ok(b"1234"));

        let mut size = 0;
        let result = call_read_persistent_value(&mut ops, "foo", None, &mut size);

        assert_eq!(result, AvbIOResult::AVB_IO_RESULT_ERROR_INSUFFICIENT_SPACE);
        assert_eq!(size, 4);
    }

    #[test]
    fn test_read_persistent_value_error() {
        let mut ops = TestOps::default();
        ops.add_persistent_value("foo", Err(IoError::Io));

        let mut size = 10;
        let mut buffer = [b'.'; 8];
        let result = call_read_persistent_value(&mut ops, "foo", Some(&mut buffer), &mut size);

        assert_eq!(result, AvbIOResult::AVB_IO_RESULT_ERROR_IO);
        assert_eq!(size, 0);
        assert_eq!(&buffer[..], b"........");
    }

    #[test]
    fn test_read_persistent_value_unknown() {
        let mut ops = TestOps::default();

        let mut size = 10;
        let mut buffer = [b'.'; 8];
        let result = call_read_persistent_value(&mut ops, "foo", Some(&mut buffer), &mut size);

        assert_eq!(result, AvbIOResult::AVB_IO_RESULT_ERROR_NO_SUCH_VALUE);
        assert_eq!(size, 0);
        assert_eq!(&buffer[..], b"........");
    }

    #[test]
    fn test_write_persistent_value() {
        let mut ops = TestOps::default();

        let result = call_write_persistent_value(&mut ops, "foo", Some(b"1234"));

        assert_eq!(result, AvbIOResult::AVB_IO_RESULT_OK);
        assert_eq!(
            ops.persistent_values.get("foo").unwrap().as_ref().unwrap(),
            b"1234"
        );
    }

    #[test]
    fn test_write_persistent_value_overwrite_existing() {
        let mut ops = TestOps::default();
        ops.add_persistent_value("foo", Ok(b"1234"));

        let result = call_write_persistent_value(&mut ops, "foo", Some(b"5678"));

        assert_eq!(result, AvbIOResult::AVB_IO_RESULT_OK);
        assert_eq!(
            ops.persistent_values.get("foo").unwrap().as_ref().unwrap(),
            b"5678"
        );
    }

    #[test]
    fn test_write_persistent_value_erase_existing() {
        let mut ops = TestOps::default();
        ops.add_persistent_value("foo", Ok(b"1234"));

        let result = call_write_persistent_value(&mut ops, "foo", None);

        assert_eq!(result, AvbIOResult::AVB_IO_RESULT_OK);
        assert!(ops.persistent_values.is_empty());
    }

    #[test]
    fn test_write_persistent_value_error() {
        let mut ops = TestOps::default();
        ops.add_persistent_value("foo", Err(IoError::NoSuchValue));

        let result = call_write_persistent_value(&mut ops, "foo", Some(b"1234"));

        assert_eq!(result, AvbIOResult::AVB_IO_RESULT_ERROR_NO_SUCH_VALUE);
    }
}
