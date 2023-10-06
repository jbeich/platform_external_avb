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
    avb_slot_verify, avb_slot_verify_data_free, AvbHashtreeErrorMode, AvbPartitionData,
    AvbSlotVerifyData, AvbSlotVerifyFlags, AvbVBMetaData,
};
use bitflags::bitflags;
use core::{
    ffi::{c_char, CStr},
    marker::PhantomData,
    ptr::{null, null_mut},
    slice,
};

/// Wraps a raw C `AvbVBMetaData` struct.
///
/// This provides a Rust safe view over the raw data; no copies are made.
//
// `repr(transparent)` guarantees that size and alignment match the underlying type exactly, so that
// we can cast the array of `AvbVBMetaData` structs directly into a slice of `VbmetaData` wrappers
// without allocating any additional memory.
#[repr(transparent)]
pub struct VbmetaData(AvbVBMetaData);

impl VbmetaData {
    pub fn partition_name(&self) -> &CStr {
        debug_assert!(!self.0.partition_name.is_null());
        // SAFETY:
        // * libavb gives us a properly-allocated and nul-terminated string.
        // * the returned contents remain valid and unmodified while we exist.
        unsafe { CStr::from_ptr(self.0.partition_name) }
    }

    pub fn data(&self) -> &[u8] {
        debug_assert!(!self.0.vbmeta_data.is_null());
        // SAFETY:
        // * libavb gives us a properly-allocated byte array.
        // * the returned contents remain valid and unmodified while we exist.
        unsafe { slice::from_raw_parts(self.0.vbmeta_data, self.0.vbmeta_size) }
    }

    pub fn verify_result(&self) -> Result<(), VbmetaVerifyError> {
        vbmeta_verify_enum_to_result(self.0.verify_result)
    }
}

/// Wraps a raw C `AvbPartitionData` struct.
///
/// This provides a Rust safe view over the raw data; no copies are made.
#[repr(transparent)]
pub struct PartitionData(AvbPartitionData);

impl PartitionData {
    pub fn partition_name(&self) -> &CStr {
        debug_assert!(!self.0.partition_name.is_null());
        // SAFETY:
        // * libavb gives us a properly-allocated and nul-terminated string.
        // * the returned contents remain valid and unmodified while we exist.
        unsafe { CStr::from_ptr(self.0.partition_name) }
    }

    pub fn data(&self) -> &[u8] {
        debug_assert!(!self.0.data.is_null());
        // SAFETY:
        // * libavb gives us a properly-allocated byte array.
        // * the returned contents remain valid and unmodified while we exist.
        unsafe { slice::from_raw_parts(self.0.data, self.0.data_size) }
    }

    pub fn preloaded(&self) -> bool {
        self.0.preloaded
    }

    pub fn verify_result(&self) -> Result<(), SlotVerifyError> {
        slot_verify_enum_to_result(self.0.verify_result)
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
    /// Returns:
    /// The new object, or `SlotVerifyError` if `data` was `NULL`.
    ///
    /// Safety:
    /// * `data` must be a valid `AvbSlotVerifyData` object created by libavb
    /// * after calling this function, do not access `data` except through the returned object
    unsafe fn new(
        data: *mut AvbSlotVerifyData,
        ops: &'a mut dyn Ops,
    ) -> Result<Self, SlotVerifyError> {
        Ok(Self {
            // SAFETY:
            // * the caller must ensure that `data` is a valid `AvbSlotVerifyData` object
            // * we now own the (heap-allocated) object and will clean it up on drop
            raw_data: unsafe { data.as_mut() }.ok_or(SlotVerifyError::InvalidArgument)?,
            _ops: PhantomData,
        })
    }

    /// Returns the slot suffix string.
    pub fn ab_suffix(&self) -> &CStr {
        debug_assert!(!self.raw_data.ab_suffix.is_null());
        // SAFETY:
        // * libavb gives us a properly-allocated and nul-terminated string.
        // * the returned contents remain valid and unmodified while we exist.
        unsafe { CStr::from_ptr(self.raw_data.ab_suffix) }
    }

    /// Returns the `VbmetaData` structs.
    pub fn vbmeta_data(&self) -> &[VbmetaData] {
        debug_assert!(!self.raw_data.vbmeta_images.is_null());
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
        debug_assert!(!self.raw_data.loaded_partitions.is_null());
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
        debug_assert!(!self.raw_data.cmdline.is_null());
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

bitflags! {
    pub struct SlotVerifyFlags: u32 {
        const AllowVerificationError = AvbSlotVerifyFlags::AVB_SLOT_VERIFY_FLAGS_ALLOW_VERIFICATION_ERROR as u32;
        const RestartCausedByHashtreeCorruption = AvbSlotVerifyFlags::AVB_SLOT_VERIFY_FLAGS_RESTART_CAUSED_BY_HASHTREE_CORRUPTION as u32;
        const NoVbmetaPartition = AvbSlotVerifyFlags::AVB_SLOT_VERIFY_FLAGS_NO_VBMETA_PARTITION as u32;
    }
}

/// `AvbHashtreeErrorMode` wrapper.
/// See libavb docs for descriptions of each mode.
//
// This is just a thin wrapper to provide consistent naming scheme with the rest of the library,
// we don't modify the set of enums at all.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum HashtreeErrorMode {
    /// `AVB_HASHTREE_ERROR_MODE_RESTART_AND_INVALIDATE`
    RestartAndInvalidate,
    /// `AVB_HASHTREE_ERROR_MODE_RESTART`
    Restart,
    /// `AVB_HASHTREE_ERROR_MODE_EIO`
    Eio,
    /// `AVB_HASHTREE_ERROR_MODE_LOGGING`
    Logging,
    /// `AVB_HASHTREE_ERROR_MODE_MANAGED_RESTART_AND_EIO`
    RestartAndEio,
    /// `AVB_HASHTREE_ERROR_MODE_PANIC`
    Panic,
}

impl From<HashtreeErrorMode> for AvbHashtreeErrorMode {
    fn from(mode: HashtreeErrorMode) -> Self {
        match mode {
            HashtreeErrorMode::RestartAndInvalidate => {
                AvbHashtreeErrorMode::AVB_HASHTREE_ERROR_MODE_RESTART_AND_INVALIDATE
            }
            HashtreeErrorMode::Restart => AvbHashtreeErrorMode::AVB_HASHTREE_ERROR_MODE_RESTART,
            HashtreeErrorMode::Eio => AvbHashtreeErrorMode::AVB_HASHTREE_ERROR_MODE_EIO,
            HashtreeErrorMode::Logging => AvbHashtreeErrorMode::AVB_HASHTREE_ERROR_MODE_LOGGING,
            HashtreeErrorMode::RestartAndEio => {
                AvbHashtreeErrorMode::AVB_HASHTREE_ERROR_MODE_MANAGED_RESTART_AND_EIO
            }
            HashtreeErrorMode::Panic => AvbHashtreeErrorMode::AVB_HASHTREE_ERROR_MODE_PANIC,
        }
    }
}

impl From<AvbHashtreeErrorMode> for HashtreeErrorMode {
    fn from(mode: AvbHashtreeErrorMode) -> Self {
        match mode {
            AvbHashtreeErrorMode::AVB_HASHTREE_ERROR_MODE_RESTART_AND_INVALIDATE => {
                HashtreeErrorMode::RestartAndInvalidate
            }
            AvbHashtreeErrorMode::AVB_HASHTREE_ERROR_MODE_RESTART => HashtreeErrorMode::Restart,
            AvbHashtreeErrorMode::AVB_HASHTREE_ERROR_MODE_EIO => HashtreeErrorMode::Eio,
            AvbHashtreeErrorMode::AVB_HASHTREE_ERROR_MODE_LOGGING => HashtreeErrorMode::Logging,
            AvbHashtreeErrorMode::AVB_HASHTREE_ERROR_MODE_MANAGED_RESTART_AND_EIO => {
                HashtreeErrorMode::RestartAndEio
            }
            AvbHashtreeErrorMode::AVB_HASHTREE_ERROR_MODE_PANIC => HashtreeErrorMode::Panic,
        }
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
/// * `Ok(SlotVerifyData)` if verification completed successfully.
/// * `Err((SlotVerifyError, Some(SlotVerifyData)))` if verification completed but failed.
/// * `Err((SlotVerifyError, None))` if verification was not able to complete (e.g. I/O error).
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
) -> Result<SlotVerifyData<'a>, (SlotVerifyError, Option<SlotVerifyData<'a>>)> {
    let mut user_data = ops::UserData::new(ops);
    let mut scoped_ops = ops::ScopedAvbOps::new(&mut user_data);
    let avb_ops = scoped_ops.as_mut();

    // libavb detects the size of the `requested_partitions` array by NULL termination. Expecting
    // the Rust caller to do this would make the API much more awkward, so we populate a
    // NULL-terminated array of c-string pointers ourselves. For now we use a fixed-sized array
    // rather than dynamically allocating, 8 should be more than enough.
    const PARTITION_ARRAY_SIZE: usize = 8 + 1; // Max 8 partition names + 1 for NULL terminator.
    if requested_partitions.len() >= PARTITION_ARRAY_SIZE {
        return Err((SlotVerifyError::Oom, None));
    }
    let mut partitions_array = [null() as *const c_char; PARTITION_ARRAY_SIZE];
    for (source, dest) in requested_partitions.iter().zip(partitions_array.iter_mut()) {
        *dest = source.as_ptr();
    }

    // To be more Rust idiomatic we allow `ab_suffix` to be `None`, but libavb requires a valid
    // pointer to an empty string in this case, not NULL.
    let ab_suffix = ab_suffix.unwrap_or(CStr::from_bytes_with_nul(b"\0").unwrap());

    let mut out_data: *mut AvbSlotVerifyData = null_mut();

    // SAFETY:
    // * we've properly initialized all objects passed into libavb.
    // * if `out_data` is non-null on return, we take ownership via `SlotVerifyData`.
    let result = slot_verify_enum_to_result(unsafe {
        avb_slot_verify(
            avb_ops,
            partitions_array.as_ptr(),
            ab_suffix.as_ptr(),
            flags.bits(),
            hashtree_error_mode.into(),
            &mut out_data,
        )
    });

    // If `out_data` is non-null, take ownership so memory gets released on drop.
    let data = match out_data.is_null() {
        true => None,
        // SAFETY: `out_data` was properly allocated by libavb and ownership has passed to us.
        false => Some(unsafe { SlotVerifyData::new(out_data, ops).map_err(|e| (e, None))? }),
    };

    // Fold the verify data into both sides of the returned `Result`.
    match result {
        Ok(()) => Ok(data.unwrap()), // libavb will always provide verification data on success.
        Err(e) => Err((e, data)),    // verification data may also be provided on failure.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::ops::tests::TestOps;
    use std::{ffi::CString, fs};

    // These constants must match the values used to create the images in Android.bp.
    const TEST_IMAGE_PATH: &str = "test_image.img";
    const TEST_VBMETA_PATH: &str = "test_vbmeta.img";
    const TEST_VBMETA_2_PARTITIONS_PATH: &str = "test_vbmeta_2_parts.img";
    const TEST_PUBLIC_KEY_PATH: &str = "data/testkey_rsa4096_pub.bin";
    const TEST_PARTITION_NAME: &str = "test_part";
    const TEST_PARTITION_2_NAME: &str = "test_part_2";
    const TEST_VBMETA_ROLLBACK_LOCATION: usize = 0; // Default value, we don't explicitly set this.

    /// Initializes a `TestOps` object such that verification on the image in `TEST_PARTITION_NAME`
    /// will be successful.
    fn successful_test_ops() -> TestOps {
        let mut ops = TestOps::default();
        ops.add_partition(TEST_PARTITION_NAME, fs::read(TEST_IMAGE_PATH).unwrap());
        ops.add_partition("vbmeta", fs::read(TEST_VBMETA_PATH).unwrap());
        ops.add_vbmeta_key(fs::read(TEST_PUBLIC_KEY_PATH).unwrap(), None, true);
        ops.rollbacks.insert(TEST_VBMETA_ROLLBACK_LOCATION, 0);
        ops.unlock_state = Ok(false);

        ops
    }

    /// Calls `slot_verify()` using standard args for verifying the single unslotted partition
    /// `TEST_PARTITION_NAME`.
    fn verify_test_partition<'a>(
        ops: &'a mut TestOps,
    ) -> Result<SlotVerifyData<'a>, (SlotVerifyError, Option<SlotVerifyData<'a>>)> {
        slot_verify(
            ops,
            &[&CString::new(TEST_PARTITION_NAME).unwrap()],
            None,
            SlotVerifyFlags::empty(),
            HashtreeErrorMode::Eio,
        )
    }

    #[test]
    fn test_verify_partition_success() {
        let mut ops = successful_test_ops();

        let result = verify_test_partition(&mut ops);

        // Make sure the resulting `SlotVerifyData` looks correct.
        let data = result.unwrap();
        assert_eq!(data.ab_suffix().to_bytes(), b"");
        // We don't care about the exact commandline, just search for a substring we know will
        // exist to make sure the commandline is being provided to the caller correctly.
        assert!(data
            .cmdline()
            .to_str()
            .unwrap()
            .contains("androidboot.vbmeta.device_state=locked"));
        assert_eq!(data.rollback_indexes(), &[0; 32]);
        assert_eq!(data.resolved_hashtree_error_mode(), HashtreeErrorMode::Eio);

        // Check the `VbmetaData` struct looks correct.
        assert_eq!(data.vbmeta_data().len(), 1);
        let vbmeta_data = &data.vbmeta_data()[0];
        assert_eq!(vbmeta_data.partition_name().to_str().unwrap(), "vbmeta");
        assert_eq!(vbmeta_data.data(), fs::read(TEST_VBMETA_PATH).unwrap());
        assert_eq!(vbmeta_data.verify_result(), Ok(()));

        // Check the `PartitionData` struct looks correct.
        assert_eq!(data.partition_data().len(), 1);
        let partition_data = &data.partition_data()[0];
        assert_eq!(
            partition_data.partition_name().to_str().unwrap(),
            TEST_PARTITION_NAME
        );
        assert_eq!(partition_data.data(), fs::read(TEST_IMAGE_PATH).unwrap());
        assert!(!partition_data.preloaded());
        assert_eq!(partition_data.verify_result(), Ok(()));
    }

    #[test]
    fn test_verify_partition_success_preloaded() {
        let mut ops = successful_test_ops();
        // Mark the image partition to be preloaded.
        ops.partitions
            .get_mut(TEST_PARTITION_NAME)
            .unwrap()
            .preloaded = true;

        let result = verify_test_partition(&mut ops);

        let data = result.unwrap();
        let partition_data = &data.partition_data()[0];
        assert!(partition_data.preloaded());
    }

    #[test]
    fn test_verify_partition_success_multiple_partitions() {
        let mut ops = successful_test_ops();
        // Add in the contents of the second partition and overwrite the vbmeta partition to
        // include both partition descriptors.
        ops.add_partition(TEST_PARTITION_2_NAME, fs::read(TEST_IMAGE_PATH).unwrap());
        ops.add_partition("vbmeta", fs::read(TEST_VBMETA_2_PARTITIONS_PATH).unwrap());

        let result = slot_verify(
            &mut ops,
            &[
                &CString::new(TEST_PARTITION_NAME).unwrap(),
                &CString::new(TEST_PARTITION_2_NAME).unwrap(),
            ],
            None,
            SlotVerifyFlags::empty(),
            HashtreeErrorMode::Eio,
        );

        // We should still only have 1 `VbmetaData` since we only used 1 vbmeta image, but it
        // signed 2 partitions so we should have 2 `PartitionData` objects.
        let data = result.unwrap();
        assert_eq!(data.vbmeta_data().len(), 1);
        assert_eq!(data.partition_data().len(), 2);
        assert_eq!(
            data.partition_data()[0].partition_name().to_str().unwrap(),
            TEST_PARTITION_NAME
        );
        assert_eq!(
            data.partition_data()[1].partition_name().to_str().unwrap(),
            TEST_PARTITION_2_NAME
        );
    }

    #[test]
    fn test_verify_partition_fail_signature_mismatch() {
        let mut ops = successful_test_ops();
        // Flipping a bit in the image should trigger `Verification` error.
        ops.partitions
            .get_mut(TEST_PARTITION_NAME)
            .unwrap()
            .contents[0] ^= 0x01;

        let result = verify_test_partition(&mut ops);

        let (error, data) = result.unwrap_err();
        assert_eq!(error, SlotVerifyError::Verification);
        assert!(data.is_none());
    }

    #[test]
    fn test_verify_partition_fail_corrupted_vbmeta() {
        let mut ops = successful_test_ops();
        // Flipping a bit in the vbmeta header should trigger `InvalidMetadata` error.
        ops.partitions.get_mut("vbmeta").unwrap().contents[0] ^= 0x01;

        let result = verify_test_partition(&mut ops);

        let (error, data) = result.unwrap_err();
        assert_eq!(error, SlotVerifyError::InvalidMetadata);
        assert!(data.is_none());
    }

    #[test]
    fn test_verify_partition_fail_rollback_violation() {
        let mut ops = successful_test_ops();
        // Rollback violation should trigger `RollbackIndex` error.
        ops.rollbacks.insert(TEST_VBMETA_ROLLBACK_LOCATION, 1);

        let result = verify_test_partition(&mut ops);

        let (error, data) = result.unwrap_err();
        assert_eq!(error, SlotVerifyError::RollbackIndex);
        assert!(data.is_none());
    }

    #[test]
    fn test_verify_partition_fail_untrusted_vbmeta_key() {
        let mut ops = successful_test_ops();
        // Untrusted vbmeta keys hould trigger `PublicKeyRejected` error.
        ops.add_vbmeta_key(fs::read(TEST_PUBLIC_KEY_PATH).unwrap(), None, false);

        let result = verify_test_partition(&mut ops);

        let (error, data) = result.unwrap_err();
        assert_eq!(error, SlotVerifyError::PublicKeyRejected);
        assert!(data.is_none());
    }

    #[test]
    fn test_verify_partition_fail_callback_error() {
        let mut ops = successful_test_ops();
        // Callback failure should trigger `Io` error.
        ops.unlock_state = Err(IoError::Io);

        let result = verify_test_partition(&mut ops);

        let (error, data) = result.unwrap_err();
        assert_eq!(error, SlotVerifyError::Io);
        assert!(data.is_none());
    }

    #[test]
    fn test_verify_partition_fail_allow_verification_error() {
        let mut ops = successful_test_ops();
        // Flip a bit to trigger a verification error.
        ops.partitions
            .get_mut(TEST_PARTITION_NAME)
            .unwrap()
            .contents[0] ^= 0x01;

        let result = slot_verify(
            &mut ops,
            &[&CString::new(TEST_PARTITION_NAME).unwrap()],
            None,
            // Pass the flag to allow verification errors.
            SlotVerifyFlags::AllowVerificationError,
            HashtreeErrorMode::Eio,
        );

        // Verification should fail, but with the `AllowVerificationError` flag it should give
        // us back the verification data.
        let (error, data) = result.unwrap_err();
        assert_eq!(error, SlotVerifyError::Verification);

        let data = data.unwrap();
        // vbmeta verification should have succeeded since that image was still correct.
        assert_eq!(data.vbmeta_data().len(), 1);
        assert_eq!(data.vbmeta_data()[0].verify_result(), Ok(()));
        // Partition verification should have failed since we modified the image.
        assert_eq!(data.partition_data().len(), 1);
        assert_eq!(
            data.partition_data()[0].verify_result(),
            Err(SlotVerifyError::Verification)
        );
    }
}
