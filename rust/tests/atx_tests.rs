// Copyright 2024, The Android Open Source Project
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

//! libavb_rs ATX tests.

use crate::{
    test_data::*,
    test_ops::{FakeVbmetaKey, TestOps},
    test_ops_one_image_one_vbmeta, verify_one_image_one_vbmeta,
};
use avb::{
    AtxPermanentAttributes, SlotVerifyError, ATX_PIK_VERSION_LOCATION, ATX_PSK_VERSION_LOCATION,
};
use ring::digest;
use std::{collections::HashMap, fs};
use zerocopy::FromBytes;

/// Initializes a `TestOps` object such that ATX verification will succeed on `TEST_PARTITION_NAME`.
fn test_atx_ops_one_image_one_vbmeta<'a>() -> TestOps<'a> {
    let mut ops = test_ops_one_image_one_vbmeta();

    // Replace vbmeta with the ATX-signed version.
    ops.add_partition("vbmeta", fs::read(TEST_ATX_VBMETA_PATH).unwrap());

    // Tell `ops` to use ATX and to route the default key through ATX validation.
    ops.use_atx = true;
    ops.vbmeta_key = FakeVbmetaKey::Atx;

    // Add the ATX permanent attributes.
    let perm_attr_bytes = fs::read(TEST_ATX_PERMANENT_ATTRIBUTES_PATH).unwrap();
    ops.atx_permanent_attributes =
        Some(AtxPermanentAttributes::read_from(&perm_attr_bytes[..]).unwrap());
    ops.atx_permanent_attributes_hash = Some(
        digest::digest(&digest::SHA256, &perm_attr_bytes[..])
            .as_ref()
            .try_into()
            .unwrap(),
    );

    // Add the rollbacks for the ATX keys.
    ops.rollbacks
        .insert(ATX_PIK_VERSION_LOCATION, TEST_ATX_PIK_VERSION);
    ops.rollbacks
        .insert(ATX_PSK_VERSION_LOCATION, TEST_ATX_PSK_VERSION);

    ops
}

#[test]
fn atx_verify_succeeds() {
    let mut ops = test_atx_ops_one_image_one_vbmeta();

    let result = verify_one_image_one_vbmeta(&mut ops);

    assert!(result.is_ok());
}

#[test]
fn atx_verify_sets_key_rollbacks() {
    let mut ops = test_atx_ops_one_image_one_vbmeta();

    // `atx_key_versions` should start empty and be filled by the `set_key_version()` callback
    // during ATX key validation.
    assert!(ops.atx_key_versions.is_empty());

    let result = verify_one_image_one_vbmeta(&mut ops);
    assert!(result.is_ok());

    assert_eq!(
        ops.atx_key_versions,
        HashMap::from([
            (ATX_PIK_VERSION_LOCATION, TEST_ATX_PIK_VERSION),
            (ATX_PSK_VERSION_LOCATION, TEST_ATX_PSK_VERSION)
        ])
    );
}

#[test]
fn atx_verify_fails_with_pik_rollback_violation() {
    let mut ops = test_atx_ops_one_image_one_vbmeta();
    // If the image is signed with a lower key version than our rollback, it should fail to verify.
    *ops.rollbacks.get_mut(&ATX_PIK_VERSION_LOCATION).unwrap() += 1;

    let result = verify_one_image_one_vbmeta(&mut ops);

    assert_eq!(result.unwrap_err(), SlotVerifyError::PublicKeyRejected);
}

#[test]
fn atx_verify_fails_with_psk_rollback_violation() {
    let mut ops = test_atx_ops_one_image_one_vbmeta();
    // If the image is signed with a lower key version than our rollback, it should fail to verify.
    *ops.rollbacks.get_mut(&ATX_PSK_VERSION_LOCATION).unwrap() += 1;

    let result = verify_one_image_one_vbmeta(&mut ops);

    assert_eq!(result.unwrap_err(), SlotVerifyError::PublicKeyRejected);
}

#[test]
fn atx_verify_fails_with_wrong_vbmeta_key() {
    let mut ops = test_atx_ops_one_image_one_vbmeta();
    // The default non-ATX-signed vbmeta image should fail to verify.
    ops.add_partition("vbmeta", fs::read(TEST_VBMETA_PATH).unwrap());

    let result = verify_one_image_one_vbmeta(&mut ops);

    assert_eq!(result.unwrap_err(), SlotVerifyError::PublicKeyRejected);
}

#[test]
fn atx_verify_fails_with_bad_permanent_attributes_hash() {
    let mut ops = test_atx_ops_one_image_one_vbmeta();
    // The permanent attributes must match their hash.
    ops.atx_permanent_attributes_hash.as_mut().unwrap()[0] ^= 0x01;

    let result = verify_one_image_one_vbmeta(&mut ops);

    assert_eq!(result.unwrap_err(), SlotVerifyError::PublicKeyRejected);
}
