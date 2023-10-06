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
    error::{
        slot_verify_enum_to_result, vbmeta_verify_enum_to_result, SlotVerifyError,
        VbmetaVerifyError,
    },
    ops, IoError, Ops,
};
use avb_bindgen::{
    avb_slot_verify, avb_slot_verify_data_free, AvbPartitionData, AvbSlotVerifyData, AvbVBMetaData,
};
use core::{
    ffi::{c_char, CStr},
    fmt,
    marker::PhantomData,
    ptr::{null, null_mut},
    slice,
};

/// `AvbHashtreeErrorMode`; see libavb docs for descriptions of each mode.
pub use avb_bindgen::AvbHashtreeErrorMode as HashtreeErrorMode;
/// `AvbSlotVerifyFlags`; see libavb docs for descriptions of each flag.
pub use avb_bindgen::AvbSlotVerifyFlags as SlotVerifyFlags;

/// Returns `Err(SlotVerifyError::Internal)` if the given pointer is `NULL`.
fn check_nonnull<T>(ptr: *const T) -> Result<(), SlotVerifyError<'static>> {
    match ptr.is_null() {
        true => Err(SlotVerifyError::Internal),
        false => Ok(()),
    }
}

/// Writes a slice of objects to a `Formatter` using `Display` formatting.
/// This differs from `"{:?}"` as that prints all objects in the array using `Debug` formatting.
fn display_slice<T: fmt::Display>(f: &mut fmt::Formatter<'_>, s: &[T]) -> fmt::Result {
    let mut first = true;
    write!(f, "[")?;
    for item in s {
        if !first {
            write!(f, ", ")?;
        }
        write!(f, "{item}")?;
        first = false;
    }
    write!(f, "]")
}

/// Wraps a raw C `AvbVBMetaData` struct.
///
/// This provides a Rust safe view over the raw data; no copies are made.
//
// `repr(transparent)` guarantees that size and alignment match the underlying type exactly, so that
// we can cast the array of `AvbVBMetaData` structs directly into a slice of `VbmetaData` wrappers
// without allocating any additional memory.
#[repr(transparent)]
#[derive(Debug)]
pub struct VbmetaData(AvbVBMetaData);

impl VbmetaData {
    /// Validates the internal data so the accessors can be fail-free. This should be called on all
    /// `VbmetaData` objects before they are handed to the user.
    ///
    /// Normally this would be done in a `new()` function but we never instantiate `VbmetaData`
    /// objects ourselves, we just cast them from the C structs provided by libavb.
    ///
    /// Returns `Err(SlotVerifyError::Internal)` on failure.
    fn validate(&self) -> Result<(), SlotVerifyError<'static>> {
        check_nonnull(self.0.partition_name)?;
        check_nonnull(self.0.vbmeta_data)?;
        Ok(())
    }

    /// Returns the name of the partition this vbmeta image was loaded from.
    pub fn partition_name(&self) -> &CStr {
        // SAFETY:
        // * libavb gives us a properly-allocated and nul-terminated string.
        // * the returned contents remain valid and unmodified while we exist.
        unsafe { CStr::from_ptr(self.0.partition_name) }
    }

    /// Returns the vbmeta image contents.
    pub fn data(&self) -> &[u8] {
        // SAFETY:
        // * libavb gives us a properly-allocated byte array.
        // * the returned contents remain valid and unmodified while we exist.
        unsafe { slice::from_raw_parts(self.0.vbmeta_data, self.0.vbmeta_size) }
    }

    /// Returns the vbmeta verification result.
    pub fn verify_result(&self) -> Result<(), VbmetaVerifyError> {
        vbmeta_verify_enum_to_result(self.0.verify_result)
    }
}

impl fmt::Display for VbmetaData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {:?}", self.partition_name(), self.verify_result())
    }
}

/// Wraps a raw C `AvbPartitionData` struct.
///
/// This provides a Rust safe view over the raw data; no copies are made.
#[repr(transparent)]
#[derive(Debug)]
pub struct PartitionData(AvbPartitionData);

impl PartitionData {
    /// Validates the internal data so the accessors can be fail-free. This should be called on all
    /// `PartitionData` objects before they are handed to the user.
    ///
    /// Normally this would be done in a `new()` function but we never instantiate `PartitionData`
    /// objects ourselves, we just cast them from the C structs provided by libavb.
    ///
    /// Returns `Err(SlotVerifyError::Internal)` on failure.
    fn validate(&self) -> Result<(), SlotVerifyError<'static>> {
        check_nonnull(self.0.partition_name)?;
        check_nonnull(self.0.data)?;
        Ok(())
    }

    /// Returns the name of the partition this image was loaded from.
    pub fn partition_name(&self) -> &CStr {
        // SAFETY:
        // * libavb gives us a properly-allocated and nul-terminated string.
        // * the returned contents remain valid and unmodified while we exist.
        unsafe { CStr::from_ptr(self.0.partition_name) }
    }

    /// Returns the image contents.
    pub fn data(&self) -> &[u8] {
        // SAFETY:
        // * libavb gives us a properly-allocated byte array.
        // * the returned contents remain valid and unmodified while we exist.
        unsafe { slice::from_raw_parts(self.0.data, self.0.data_size) }
    }

    /// Returns whether this partition was preloaded via `get_preloaded_partition()`.
    pub fn preloaded(&self) -> bool {
        self.0.preloaded
    }

    /// Returns the verification result for this partition.
    ///
    /// Only top-level `Verification` errors will contain valid `SlotVerifyData` objects, if this
    /// individual partition returns a `Verification` error the error will always contain `None`.
    pub fn verify_result(&self) -> Result<(), SlotVerifyError<'static>> {
        slot_verify_enum_to_result(self.0.verify_result)
    }
}

/// A "(p)" after the partition name indicates a preloaded partition.
impl fmt::Display for PartitionData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let preload_token = match self.preloaded() {
            true => "(p)",
            false => "",
        };
        write!(
            f,
            "{:?}{}: {:?}",
            self.partition_name(),
            preload_token,
            self.verify_result()
        )
    }
}

/// Wraps a raw C `AvbSlotVerifyData` struct.
///
/// This provides a Rust safe view over the raw data; no copies are made.
#[derive(Debug)]
pub struct SlotVerifyData<'a> {
    /// Internally owns the underlying data and deletes it on drop.
    raw_data: &'a mut AvbSlotVerifyData,

    /// This provides the necessary lifetime information so the compiler can make sure that
    /// the `Ops` stays alive at least as long as we do.
    _ops: PhantomData<&'a dyn Ops>,
}

impl<'a> SlotVerifyData<'a> {
    /// Creates a `SlotVerifyData` wrapping the given raw `AvbSlotVerifyData`.
    ///
    /// The returned `SlotVerifyData` will take ownership of the given `AvbSlotVerifyData` and
    /// properly release the allocated memory when it drops.
    ///
    /// # Arguments
    /// * `data`: a `AvbSlotVerifyData` object created by libavb.
    /// * `ops`: the user-provided callback ops; borrowing this here ensures that any preloaded
    ///          partition data stays unmodified while `data` is wrapping it.
    ///
    /// # Returns
    /// The new object, or `Err(SlotVerifyError::Internal)` if the data looks invalid.
    ///
    /// # Safety
    /// * `data` must be a valid `AvbSlotVerifyData` object created by libavb
    /// * after calling this function, do not access `data` except through the returned object
    unsafe fn new(
        data: *mut AvbSlotVerifyData,
        ops: &'a mut dyn Ops,
    ) -> Result<Self, SlotVerifyError<'static>> {
        let ret = Self {
            // SAFETY:
            // * the caller must ensure that `data` is a valid `AvbSlotVerifyData` object
            // * we now own the (heap-allocated) object and will clean it up on drop
            raw_data: unsafe { data.as_mut() }.ok_or(SlotVerifyError::Internal)?,
            _ops: PhantomData,
        };

        // Validate all the contained data here so accessors will never fail.
        check_nonnull(ret.raw_data.ab_suffix)?;
        check_nonnull(ret.raw_data.vbmeta_images)?;
        check_nonnull(ret.raw_data.loaded_partitions)?;
        check_nonnull(ret.raw_data.cmdline)?;
        for vbmeta in ret.vbmeta_data() {
            vbmeta.validate()?;
        }
        for image in ret.partition_data() {
            image.validate()?;
        }

        Ok(ret)
    }

    /// Returns the slot suffix string.
    pub fn ab_suffix(&self) -> &CStr {
        // SAFETY:
        // * libavb gives us a properly-allocated and nul-terminated string.
        // * the returned contents remain valid and unmodified while we exist.
        unsafe { CStr::from_ptr(self.raw_data.ab_suffix) }
    }

    /// Returns the `VbmetaData` structs.
    pub fn vbmeta_data(&self) -> &[VbmetaData] {
        // SAFETY:
        // * libavb gives us a properly-allocated array of structs.
        // * the returned contents remain valid and unmodified while we exist.
        unsafe {
            slice::from_raw_parts(
                // `repr(transparent)` means we can cast between these types.
                self.raw_data.vbmeta_images as *const VbmetaData,
                self.raw_data.num_vbmeta_images,
            )
        }
    }

    /// Returns the `PartitionData` structs.
    pub fn partition_data(&self) -> &[PartitionData] {
        // SAFETY:
        // * libavb gives us a properly-allocated array of structs.
        // * the returned contents remain valid and unmodified while we exist.
        unsafe {
            slice::from_raw_parts(
                // `repr(transparent)` means we can cast between these types.
                self.raw_data.loaded_partitions as *const PartitionData,
                self.raw_data.num_loaded_partitions,
            )
        }
    }

    /// Returns the kernel commandline.
    pub fn cmdline(&self) -> &CStr {
        // SAFETY:
        // * libavb gives us a properly-allocated and nul-terminated string.
        // * the returned contents remain valid and unmodified while we exist.
        unsafe { CStr::from_ptr(self.raw_data.cmdline) }
    }

    /// Returns the rollback indices.
    pub fn rollback_indexes(&self) -> &[u64] {
        &self.raw_data.rollback_indexes[..]
    }

    /// Returns the resolved hashtree error mode.
    pub fn resolved_hashtree_error_mode(&self) -> HashtreeErrorMode {
        self.raw_data.resolved_hashtree_error_mode.into()
    }
}

impl<'a> Drop for SlotVerifyData<'a> {
    fn drop(&mut self) {
        // SAFETY:
        // * we are the exclusive owners of this object
        // * libavb created the object and requires us to free it by calling this function
        unsafe { avb_slot_verify_data_free(self.raw_data) };
    }
}

/// Implements `Display` to make it easy to print some basic information.
///
/// This implementation will print the partition name and verification status for all vbmetadata
/// and images.
impl<'a> fmt::Display for SlotVerifyData<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "vbmeta: ")?;
        display_slice(f, self.vbmeta_data())?;
        write!(f, ", images: ")?;
        display_slice(f, self.partition_data())
    }
}

/// Performs verification of the requested images.
///
/// This wraps `avb_slot_verify()` for Rust, see the original docs for more details.
///
/// # Arguments
/// * `ops`: implementation of the required verification callbacks.
/// * `requested_partition`: the set of partition names to verify.
/// * `ab_suffix`: the slot suffix to append to the partition names, or None.
/// * `flags`: flags to configure verification.
/// * `hashtree_error_mode`: desired error handling behavior.
///
/// # Returns
/// `Ok` if verification completed successfully, the verification error otherwise. `SlotVerifyData`
/// will be returned in two cases:
///
/// 1. always returned on verification success
/// 2. if `AllowVerificationError` is given in `flags`, it will also be returned on verification
///    failure
///
/// If a `SlotVerifyData` is returned, it will borrow the provided `ops`. This is to ensure that
/// any data shared by `SlotVerifyData` and `ops` - in particular preloaded partition contents -
/// is not modified until `SlotVerifyData` is dropped.
pub fn slot_verify<'a>(
    ops: &'a mut dyn Ops,
    requested_partitions: &[&CStr],
    ab_suffix: Option<&CStr>,
    flags: SlotVerifyFlags,
    hashtree_error_mode: HashtreeErrorMode,
) -> Result<SlotVerifyData<'a>, SlotVerifyError<'a>> {
    let mut user_data = ops::UserData::new(ops);
    let mut scoped_ops = ops::ScopedAvbOps::new(&mut user_data);
    let avb_ops = scoped_ops.as_mut();

    // libavb detects the size of the `requested_partitions` array by NULL termination. Expecting
    // the Rust caller to do this would make the API much more awkward, so we populate a
    // NULL-terminated array of c-string pointers ourselves. For now we use a fixed-sized array
    // rather than dynamically allocating, 8 should be more than enough.
    const MAX_PARTITION_ARRAY_SIZE: usize = 8 + 1; // Max 8 partition names + 1 for NULL terminator.
    if requested_partitions.len() >= MAX_PARTITION_ARRAY_SIZE {
        return Err(SlotVerifyError::Internal);
    }
    let mut partitions_array = [null() as *const c_char; MAX_PARTITION_ARRAY_SIZE];
    for (source, dest) in requested_partitions.iter().zip(partitions_array.iter_mut()) {
        *dest = source.as_ptr();
    }

    // To be more Rust idiomatic we allow `ab_suffix` to be `None`, but libavb requires a valid
    // pointer to an empty string in this case, not NULL.
    let ab_suffix = ab_suffix.unwrap_or(CStr::from_bytes_with_nul(b"\0").unwrap());

    let mut out_data: *mut AvbSlotVerifyData = null_mut();

    // Call the libavb verification function.
    //
    // Note: do not use the `?` operator to return-early here; in some cases `out_data` will be
    // allocated and returned even on verification failure, and we need to take ownership of it
    // or else the memory will leak.
    //
    // SAFETY:
    // * we've properly initialized all objects passed into libavb.
    // * if `out_data` is non-null on return, we take ownership via `SlotVerifyData`.
    let result = slot_verify_enum_to_result(unsafe {
        avb_slot_verify(
            avb_ops,
            partitions_array.as_ptr(),
            ab_suffix.as_ptr(),
            flags,
            hashtree_error_mode.into(),
            &mut out_data,
        )
    });

    // If `out_data` is non-null, take ownership so memory gets released on drop.
    let data = match out_data.is_null() {
        true => None,
        // SAFETY: `out_data` was properly allocated by libavb and ownership has passed to us.
        false => Some(unsafe { SlotVerifyData::new(out_data, ops)? }),
    };

    // Fold the verify data into the result.
    match result {
        // libavb will always provide verification data on success.
        Ok(()) => Ok(data.unwrap()),
        // Data may also be provided on verification failure, fold it into the error.
        Err(SlotVerifyError::Verification(None)) => Err(SlotVerifyError::Verification(data)),
        // No other error provides verification data.
        Err(e) => Err(e),
    }
}
