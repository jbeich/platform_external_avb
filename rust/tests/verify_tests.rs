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

//! libavb_rs verification tests.

use crate::test_ops::TestOps;
use avb::{
    slot_verify, HashtreeErrorMode, IoError, SlotVerifyData, SlotVerifyError, SlotVerifyFlags,
};
use std::{collections::HashMap, ffi::CString, fs};
#[cfg(feature = "uuid")]
use uuid::{uuid, Uuid};

// These constants must match the values used to create the images in Android.bp.
const TEST_IMAGE_PATH: &str = "test_image.img";
const TEST_IMAGE_SIZE: usize = 16 * 1024;
const TEST_VBMETA_PATH: &str = "test_vbmeta.img";
const TEST_VBMETA_2_PARTITIONS_PATH: &str = "test_vbmeta_2_parts.img";
const TEST_VBMETA_PERSISTENT_DIGEST_PATH: &str = "test_vbmeta_persistent_digest.img";
const TEST_IMAGE_WITH_VBMETA_FOOTER_PATH: &str = "avbrs_test_image_with_vbmeta_footer.img";
const TEST_PUBLIC_KEY_PATH: &str = "data/testkey_rsa4096_pub.bin";
const TEST_PARTITION_NAME: &str = "test_part";
const TEST_PARTITION_SLOT_C_NAME: &str = "test_part_c";
const TEST_PARTITION_2_NAME: &str = "test_part_2";
const TEST_PARTITION_PERSISTENT_DIGEST_NAME: &str = "test_part_persistent_digest";
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
) -> Result<SlotVerifyData<'a>, SlotVerifyError<'a>> {
    slot_verify(
        ops,
        &[&CString::new(TEST_PARTITION_NAME).unwrap()],
        None,
        SlotVerifyFlags::None,
        HashtreeErrorMode::Eio,
    )
}

/// Modifies the partition contents by flipping a bit.
fn modify_partition_contents(ops: &mut TestOps, partition: &str) {
    ops.partitions.get_mut(partition).unwrap().contents[0] ^= 0x01;
}

#[test]
fn one_image_one_vbmeta_passes_verification_with_correct_data() {
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
    assert!(partition_data.verify_result().is_ok());
}

#[test]
fn preloaded_image_passes_verification() {
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
fn slotted_partition_passes_verification() {
    let mut ops = successful_test_ops();
    // Move the partitions to a "_c" slot.
    ops.partitions.clear();
    ops.add_partition(
        TEST_PARTITION_SLOT_C_NAME,
        fs::read(TEST_IMAGE_PATH).unwrap(),
    );
    ops.add_partition("vbmeta_c", fs::read(TEST_VBMETA_PATH).unwrap());

    let result = slot_verify(
        &mut ops,
        &[&CString::new(TEST_PARTITION_NAME).unwrap()],
        Some(&CString::new("_c").unwrap()),
        SlotVerifyFlags::None,
        HashtreeErrorMode::Eio,
    );

    let data = result.unwrap();
    assert_eq!(data.ab_suffix().to_bytes(), b"_c");
}

#[test]
fn two_images_one_vbmeta_passes_verification() {
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
        SlotVerifyFlags::None,
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
fn combined_image_vbmeta_partition_passes_verification() {
    let mut ops = TestOps::default();
    // Register the single combined image + vbmeta in `TEST_PARTITION_NAME`.
    ops.add_partition(
        TEST_PARTITION_NAME,
        fs::read(TEST_IMAGE_WITH_VBMETA_FOOTER_PATH).unwrap(),
    );
    // For a combined image we need to register the public key specifically for this partition.
    ops.add_vbmeta_key_for_partition(
        fs::read(TEST_PUBLIC_KEY_PATH).unwrap(),
        None,
        true,
        TEST_PARTITION_NAME,
        TEST_VBMETA_ROLLBACK_LOCATION as u32,
    );
    ops.rollbacks.insert(TEST_VBMETA_ROLLBACK_LOCATION, 0);
    ops.unlock_state = Ok(false);

    let result = slot_verify(
        &mut ops,
        &[&CString::new(TEST_PARTITION_NAME).unwrap()],
        None,
        // Tell libavb that the vbmeta image is embedded, not in its own partition.
        SlotVerifyFlags::NoVbmetaPartition,
        HashtreeErrorMode::Eio,
    );

    let data = result.unwrap();

    // Vbmeta should indicate that it came from `TEST_PARTITION_NAME`.
    assert_eq!(data.vbmeta_data().len(), 1);
    let vbmeta_data = &data.vbmeta_data()[0];
    assert_eq!(
        vbmeta_data.partition_name().to_str().unwrap(),
        TEST_PARTITION_NAME
    );

    // Partition should indicate that it came from `TEST_PARTITION_NAME`, but only contain the
    // image contents.
    assert_eq!(data.partition_data().len(), 1);
    let partition_data = &data.partition_data()[0];
    assert_eq!(
        partition_data.partition_name().to_str().unwrap(),
        TEST_PARTITION_NAME
    );
    assert_eq!(partition_data.data(), fs::read(TEST_IMAGE_PATH).unwrap());
}

#[test]
fn persistent_digest_verification_updates_persistent_value() {
    // With persistent digests, the image hash isn't stored in the descriptor, but is instead
    // calculated on-demand and stored into a named persistent value. So our test image can contain
    // anything, but does have to match the size indicated by the descriptor.
    let image_contents = vec![0xAA; TEST_IMAGE_SIZE];

    let mut ops = successful_test_ops();
    ops.partitions.clear();
    // Use the vbmeta image with the persistent digest descriptor.
    ops.add_partition(
        "vbmeta",
        fs::read(TEST_VBMETA_PERSISTENT_DIGEST_PATH).unwrap(),
    );
    // Register the image contents to be stored via persistent digest.
    ops.add_partition(
        TEST_PARTITION_PERSISTENT_DIGEST_NAME,
        image_contents.clone(),
    );

    {
        let result = slot_verify(
            &mut ops,
            &[&CString::new(TEST_PARTITION_PERSISTENT_DIGEST_NAME).unwrap()],
            None,
            SlotVerifyFlags::None,
            HashtreeErrorMode::Eio,
        );
        let data = result.unwrap();
        assert_eq!(data.partition_data()[0].data(), image_contents);
    } // Drop `result` here so it releases `ops` and we can use it again.

    assert!(ops.persistent_values.contains_key(&format!(
        "avb.persistent_digest.{TEST_PARTITION_PERSISTENT_DIGEST_NAME}"
    )));
}

#[cfg(feature = "uuid")]
#[test]
fn successful_verification_substitutes_partition_guid() {
    let mut ops = successful_test_ops();
    ops.partitions.get_mut("vbmeta").unwrap().uuid = uuid!("01234567-89ab-cdef-0123-456789abcdef");

    let result = verify_test_partition(&mut ops);

    let data = result.unwrap();
    assert!(data
        .cmdline()
        .to_str()
        .unwrap()
        .contains("androidboot.vbmeta.device=PARTUUID=01234567-89ab-cdef-0123-456789abcdef"));
}

#[test]
fn corrupted_image_fails_verification() {
    let mut ops = successful_test_ops();
    modify_partition_contents(&mut ops, TEST_PARTITION_NAME);

    let result = verify_test_partition(&mut ops);

    let error = result.unwrap_err();
    assert!(matches!(error, SlotVerifyError::Verification(None)));
}

#[test]
fn read_partition_callback_error_fails_verification() {
    let mut ops = successful_test_ops();
    ops.partitions.remove(TEST_PARTITION_NAME);

    let result = verify_test_partition(&mut ops);

    let error = result.unwrap_err();
    assert!(matches!(error, SlotVerifyError::Io));
}

#[test]
fn undersized_partition_fails_verification() {
    let mut ops = successful_test_ops();
    ops.partitions
        .get_mut(TEST_PARTITION_NAME)
        .unwrap()
        .contents
        .pop();

    let result = verify_test_partition(&mut ops);

    let error = result.unwrap_err();
    assert!(matches!(error, SlotVerifyError::Io));
}

#[test]
fn corrupted_vbmeta_fails_verification() {
    let mut ops = successful_test_ops();
    modify_partition_contents(&mut ops, "vbmeta");

    let result = verify_test_partition(&mut ops);

    let error = result.unwrap_err();
    assert!(matches!(error, SlotVerifyError::InvalidMetadata));
}

#[test]
fn rollback_violation_fails_verification() {
    let mut ops = successful_test_ops();
    // Device with rollback = 1 should refuse to boot image with rollback = 0.
    ops.rollbacks.insert(TEST_VBMETA_ROLLBACK_LOCATION, 1);

    let result = verify_test_partition(&mut ops);

    let error = result.unwrap_err();
    assert!(matches!(error, SlotVerifyError::RollbackIndex));
}

#[test]
fn rollback_callback_error_fails_verification() {
    let mut ops = successful_test_ops();
    ops.rollbacks.clear();

    let result = verify_test_partition(&mut ops);

    let error = result.unwrap_err();
    assert!(matches!(error, SlotVerifyError::Io));
}

#[test]
fn untrusted_vbmeta_keys_fails_verification() {
    let mut ops = successful_test_ops();
    ops.add_vbmeta_key(fs::read(TEST_PUBLIC_KEY_PATH).unwrap(), None, false);

    let result = verify_test_partition(&mut ops);

    let error = result.unwrap_err();
    assert!(matches!(error, SlotVerifyError::PublicKeyRejected));
}

#[test]
fn vbmeta_keys_callback_error_fails_verification() {
    let mut ops = successful_test_ops();
    ops.vbmeta_keys.clear();

    let result = verify_test_partition(&mut ops);

    let error = result.unwrap_err();
    assert!(matches!(error, SlotVerifyError::Io));
}

#[test]
fn unlock_state_callback_error_fails_verification() {
    let mut ops = successful_test_ops();
    ops.unlock_state = Err(IoError::Io);

    let result = verify_test_partition(&mut ops);

    let error = result.unwrap_err();
    assert!(matches!(error, SlotVerifyError::Io));
}

#[test]
fn corrupted_image_with_allow_verification_error_flag_fails_verification_with_data() {
    let mut ops = successful_test_ops();
    modify_partition_contents(&mut ops, TEST_PARTITION_NAME);

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
    let error = result.unwrap_err();
    let data = match error {
        SlotVerifyError::Verification(Some(data)) => data,
        _ => panic!("Expected verification data to exist"),
    };

    // vbmeta verification should have succeeded since that image was still correct.
    assert_eq!(data.vbmeta_data().len(), 1);
    assert_eq!(data.vbmeta_data()[0].verify_result(), Ok(()));
    // Partition verification should have failed since we modified the image.
    assert_eq!(data.partition_data().len(), 1);
    assert!(matches!(
        data.partition_data()[0].verify_result(),
        Err(SlotVerifyError::Verification(None))
    ));
}

#[test]
fn one_image_one_vbmeta_verification_data_display() {
    let mut ops = successful_test_ops();

    let result = verify_test_partition(&mut ops);

    let data = result.unwrap();
    assert_eq!(
        format!("{data}"),
        r#"vbmeta: ["vbmeta": Ok], images: ["test_part": Ok]"#
    );
}

#[test]
fn preloaded_image_verification_data_display() {
    let mut ops = successful_test_ops();
    ops.partitions
        .get_mut(TEST_PARTITION_NAME)
        .unwrap()
        .preloaded = true;

    let result = verify_test_partition(&mut ops);

    let data = result.unwrap();
    assert_eq!(
        format!("{data}"),
        r#"vbmeta: ["vbmeta": Ok], images: ["test_part"(p): Ok]"#
    );
}

#[test]
fn two_images_one_vbmeta_verification_data_display() {
    let mut ops = successful_test_ops();
    ops.add_partition(TEST_PARTITION_2_NAME, fs::read(TEST_IMAGE_PATH).unwrap());
    ops.add_partition("vbmeta", fs::read(TEST_VBMETA_2_PARTITIONS_PATH).unwrap());

    let result = slot_verify(
        &mut ops,
        &[
            &CString::new(TEST_PARTITION_NAME).unwrap(),
            &CString::new(TEST_PARTITION_2_NAME).unwrap(),
        ],
        None,
        SlotVerifyFlags::None,
        HashtreeErrorMode::Eio,
    );

    let data = result.unwrap();
    assert_eq!(
        format!("{data}"),
        r#"vbmeta: ["vbmeta": Ok], images: ["test_part": Ok, "test_part_2": Ok]"#
    );
}

#[test]
fn corrupted_image_verification_data_display() {
    let mut ops = successful_test_ops();
    modify_partition_contents(&mut ops, TEST_PARTITION_NAME);

    let result = slot_verify(
        &mut ops,
        &[&CString::new(TEST_PARTITION_NAME).unwrap()],
        None,
        SlotVerifyFlags::AllowVerificationError,
        HashtreeErrorMode::Eio,
    );

    let error = result.unwrap_err();
    let data = match error {
        SlotVerifyError::Verification(Some(data)) => data,
        _ => panic!("Expected verification data to exist"),
    };
    assert_eq!(
        format!("{data}"),
        r#"vbmeta: ["vbmeta": Ok], images: ["test_part": Verification failure]"#
    );
}
