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

//! libavb_rs certificate tests.

use crate::{
    build_test_ops_one_image_one_vbmeta,
    test_data::*,
    test_ops::{FakeVbmetaKey, TestOps},
    verify_one_image_one_vbmeta,
};
use avb::{
    CertPermanentAttributes, SlotVerifyError, CERT_PIK_VERSION_LOCATION, CERT_PSK_VERSION_LOCATION,
};
use hex::decode;
use std::{collections::HashMap, fs};
use zerocopy::FromBytes;

/// Initializes a `TestOps` object such that cert verification will succeed on `TEST_PARTITION_NAME`.
fn build_test_cert_ops_one_image_one_vbmeta<'a>() -> TestOps<'a> {
    let mut ops = build_test_ops_one_image_one_vbmeta();

    // Replace vbmeta with the cert-signed version.
    ops.add_partition("vbmeta", fs::read(TEST_CERT_VBMETA_PATH).unwrap());

    // Tell `ops` to use cert APIs and to route the default key through cert validation.
    ops.use_cert = true;
    ops.vbmeta_key = FakeVbmetaKey::Cert;

    // Add the libavb_cert permanent attributes.
    let perm_attr_bytes = fs::read(TEST_CERT_PERMANENT_ATTRIBUTES_PATH).unwrap();
    ops.cert_permanent_attributes =
        Some(CertPermanentAttributes::read_from(&perm_attr_bytes[..]).unwrap());
    ops.cert_permanent_attributes_hash = Some(
        decode(TEST_CERT_PERMANENT_ATTRIBUTES_HASH_HEX)
            .unwrap()
            .try_into()
            .unwrap(),
    );

    // Add the rollbacks for the cert keys.
    ops.rollbacks
        .insert(CERT_PIK_VERSION_LOCATION, TEST_CERT_PIK_VERSION);
    ops.rollbacks
        .insert(CERT_PSK_VERSION_LOCATION, TEST_CERT_PSK_VERSION);

    ops
}

#[test]
fn cert_verify_succeeds() {
    let mut ops = build_test_cert_ops_one_image_one_vbmeta();

    let result = verify_one_image_one_vbmeta(&mut ops);

    assert!(result.is_ok());
}

#[test]
fn cert_verify_sets_key_rollbacks() {
    let mut ops = build_test_cert_ops_one_image_one_vbmeta();

    // `cert_key_versions` should start empty and be filled by the `set_key_version()` callback
    // during cert key validation.
    assert!(ops.cert_key_versions.is_empty());

    let result = verify_one_image_one_vbmeta(&mut ops);
    assert!(result.is_ok());

    assert_eq!(
        ops.cert_key_versions,
        HashMap::from([
            (CERT_PIK_VERSION_LOCATION, TEST_CERT_PIK_VERSION),
            (CERT_PSK_VERSION_LOCATION, TEST_CERT_PSK_VERSION)
        ])
    );
}

#[test]
fn cert_verify_fails_with_pik_rollback_violation() {
    let mut ops = build_test_cert_ops_one_image_one_vbmeta();
    // If the image is signed with a lower key version than our rollback, it should fail to verify.
    *ops.rollbacks.get_mut(&CERT_PIK_VERSION_LOCATION).unwrap() += 1;

    let result = verify_one_image_one_vbmeta(&mut ops);

    assert_eq!(result.unwrap_err(), SlotVerifyError::PublicKeyRejected);
}

#[test]
fn cert_verify_fails_with_psk_rollback_violation() {
    let mut ops = build_test_cert_ops_one_image_one_vbmeta();
    // If the image is signed with a lower key version than our rollback, it should fail to verify.
    *ops.rollbacks.get_mut(&CERT_PSK_VERSION_LOCATION).unwrap() += 1;

    let result = verify_one_image_one_vbmeta(&mut ops);

    assert_eq!(result.unwrap_err(), SlotVerifyError::PublicKeyRejected);
}

#[test]
fn cert_verify_fails_with_wrong_vbmeta_key() {
    let mut ops = build_test_cert_ops_one_image_one_vbmeta();
    // The default non-cert vbmeta image should fail to verify.
    ops.add_partition("vbmeta", fs::read(TEST_VBMETA_PATH).unwrap());

    let result = verify_one_image_one_vbmeta(&mut ops);

    assert_eq!(result.unwrap_err(), SlotVerifyError::PublicKeyRejected);
}

#[test]
fn cert_verify_fails_with_bad_permanent_attributes_hash() {
    let mut ops = build_test_cert_ops_one_image_one_vbmeta();
    // The permanent attributes must match their hash.
    ops.cert_permanent_attributes_hash.as_mut().unwrap()[0] ^= 0x01;

    let result = verify_one_image_one_vbmeta(&mut ops);

    assert_eq!(result.unwrap_err(), SlotVerifyError::PublicKeyRejected);
}
