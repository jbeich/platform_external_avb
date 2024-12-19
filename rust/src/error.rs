// Copyright 2022, The Android Open Source Project
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

//! Error types used in libavb.
//!
//! There are a few advantages of providing these custom types rather than exposing the raw bindgen
//! enums directly:
//! * More idiomatic error handling
//!   * C code defines a "status" enum that can contain either OK or an error, whereas Rust prefers
//!     error-only enums to use with `Result<>` e.g. `Result<(), IoError>`. An "OK" status doesn't
//!     make sense when used with `Result<>`.
//! * Better naming e.g. `IoError::Oom` vs the redundant `AvbIoResult::AVB_IO_RESULT_ERROR_OOM`
//! * We can implement traits such as `Display` for added convenience.

// The naming scheme can be a bit confusing due to the re-use of "result" in a few places:
// * `Avb*Result`: raw libavb enums generated by bindgen, containing errors and "OK". Internal-only;
//                 library users should never have to use these types.
// * `*Error`: `Avb*Result` wrappers which only contain error conditions, not "OK". Should be
//             wrapped in a Rust `Result<>` in public API.
// * `Result<T, *Error>`: top-level `Result<>` type used in this library's public API.

use crate::SlotVerifyData;
use avb_bindgen::{AvbIOResult, AvbSlotVerifyResult, AvbVBMetaVerifyResult};
use core::{fmt, str::Utf8Error};

/// `AvbSlotVerifyResult` error wrapper.
///
/// Some of the errors can contain the resulting `SlotVerifyData` if the `AllowVerificationError`
/// flag was passed into `slot_verify()`.
#[derive(Debug, PartialEq, Eq)]
pub enum SlotVerifyError<'a> {
    /// `AVB_SLOT_VERIFY_RESULT_ERROR_INVALID_ARGUMENT`
    InvalidArgument,
    /// `AVB_SLOT_VERIFY_RESULT_ERROR_INVALID_METADATA`
    InvalidMetadata,
    /// `AVB_SLOT_VERIFY_RESULT_ERROR_IO`
    Io,
    /// `AVB_SLOT_VERIFY_RESULT_ERROR_OOM`
    Oom,
    /// `AVB_SLOT_VERIFY_RESULT_ERROR_PUBLIC_KEY_REJECTED`
    PublicKeyRejected(Option<SlotVerifyData<'a>>),
    /// `AVB_SLOT_VERIFY_RESULT_ERROR_ROLLBACK_INDEX`
    RollbackIndex(Option<SlotVerifyData<'a>>),
    /// `AVB_SLOT_VERIFY_RESULT_ERROR_UNSUPPORTED_VERSION`
    UnsupportedVersion,
    /// `AVB_SLOT_VERIFY_RESULT_ERROR_VERIFICATION`
    Verification(Option<SlotVerifyData<'a>>),
    /// Unexpected internal error. This does not have a corresponding libavb error code.
    Internal,
}

/// `Result` type for `SlotVerifyError` errors.
pub type SlotVerifyResult<'a, T> = Result<T, SlotVerifyError<'a>>;

/// `Result` type for `SlotVerifyError` errors without any `SlotVerifyData`.
///
/// If the contained error will never hold a `SlotVerifyData`, this is easier to work with compared
/// to `SlotVerifyResult` due to the static lifetime bound.
pub type SlotVerifyNoDataResult<T> = SlotVerifyResult<'static, T>;

impl<'a> SlotVerifyError<'a> {
    /// Returns a copy of this error without any contained `SlotVerifyData`.
    ///
    /// This can simplify usage if the user doesn't care about the `SlotVerifyData` by turning the
    /// current lifetime bound into `'static`.
    pub fn without_verify_data(&self) -> SlotVerifyError<'static> {
        match self {
            Self::InvalidArgument => SlotVerifyError::InvalidArgument,
            Self::InvalidMetadata => SlotVerifyError::InvalidMetadata,
            Self::Io => SlotVerifyError::Io,
            Self::Oom => SlotVerifyError::Oom,
            Self::PublicKeyRejected(_) => SlotVerifyError::PublicKeyRejected(None),
            Self::RollbackIndex(_) => SlotVerifyError::RollbackIndex(None),
            Self::UnsupportedVersion => SlotVerifyError::UnsupportedVersion,
            Self::Verification(_) => SlotVerifyError::Verification(None),
            Self::Internal => SlotVerifyError::Internal,
        }
    }

    /// Returns a `SlotVerifyData` which can be provided with non-fatal errors in case
    /// `AllowVerificationError` flag was passed into `slot_verify()`.
    pub fn verification_data(&self) -> Option<&SlotVerifyData<'a>> {
        match self {
            SlotVerifyError::PublicKeyRejected(data)
            | SlotVerifyError::RollbackIndex(data)
            | SlotVerifyError::Verification(data) => data.as_ref(),
            _ => None,
        }
    }
}

impl<'a> fmt::Display for SlotVerifyError<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::InvalidArgument => write!(f, "Invalid parameters"),
            Self::InvalidMetadata => write!(f, "Invalid metadata"),
            Self::Io => write!(f, "I/O error"),
            Self::Oom => write!(f, "Unable to allocate memory"),
            Self::PublicKeyRejected(_) => write!(f, "Public key rejected or data not signed"),
            Self::RollbackIndex(_) => write!(f, "Rollback index violation"),
            Self::UnsupportedVersion => write!(f, "Unsupported vbmeta version"),
            Self::Verification(_) => write!(f, "Verification failure"),
            Self::Internal => write!(f, "Internal error"),
        }
    }
}

/// Converts a bindgen `AvbSlotVerifyResult` enum to a `SlotVerifyNoDataResult<>`, mapping
/// `AVB_SLOT_VERIFY_RESULT_OK` to the Rust equivalent `Ok(())` and errors to the corresponding
/// `Err(SlotVerifyError)`.
///
/// An error returned here will always have a `None` `SlotVerifyData`; the data should be added
/// in later if it exists.
///
/// This function is also important to serve as a compile-time check that we're handling all the
/// libavb enums; if a new one is added to (or removed from) the C code, this will fail to compile
/// until it is updated to match.
pub(crate) fn slot_verify_enum_to_result(
    result: AvbSlotVerifyResult,
) -> SlotVerifyNoDataResult<()> {
    match result {
        AvbSlotVerifyResult::AVB_SLOT_VERIFY_RESULT_OK => Ok(()),
        AvbSlotVerifyResult::AVB_SLOT_VERIFY_RESULT_ERROR_INVALID_ARGUMENT => {
            Err(SlotVerifyError::InvalidArgument)
        }
        AvbSlotVerifyResult::AVB_SLOT_VERIFY_RESULT_ERROR_INVALID_METADATA => {
            Err(SlotVerifyError::InvalidMetadata)
        }
        AvbSlotVerifyResult::AVB_SLOT_VERIFY_RESULT_ERROR_IO => Err(SlotVerifyError::Io),
        AvbSlotVerifyResult::AVB_SLOT_VERIFY_RESULT_ERROR_OOM => Err(SlotVerifyError::Oom),
        AvbSlotVerifyResult::AVB_SLOT_VERIFY_RESULT_ERROR_PUBLIC_KEY_REJECTED => {
            Err(SlotVerifyError::PublicKeyRejected(None))
        }
        AvbSlotVerifyResult::AVB_SLOT_VERIFY_RESULT_ERROR_ROLLBACK_INDEX => {
            Err(SlotVerifyError::RollbackIndex(None))
        }
        AvbSlotVerifyResult::AVB_SLOT_VERIFY_RESULT_ERROR_UNSUPPORTED_VERSION => {
            Err(SlotVerifyError::UnsupportedVersion)
        }
        AvbSlotVerifyResult::AVB_SLOT_VERIFY_RESULT_ERROR_VERIFICATION => {
            Err(SlotVerifyError::Verification(None))
        }
    }
}

/// `AvbIOResult` error wrapper.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IoError {
    /// `AVB_IO_RESULT_ERROR_OOM`
    Oom,
    /// `AVB_IO_RESULT_ERROR_IO`
    Io,
    /// `AVB_IO_RESULT_ERROR_NO_SUCH_PARTITION`
    NoSuchPartition,
    /// `AVB_IO_RESULT_ERROR_RANGE_OUTSIDE_PARTITION`
    RangeOutsidePartition,
    /// `AVB_IO_RESULT_ERROR_NO_SUCH_VALUE`
    NoSuchValue,
    /// `AVB_IO_RESULT_ERROR_INVALID_VALUE_SIZE`
    InvalidValueSize,
    /// `AVB_IO_RESULT_ERROR_INSUFFICIENT_SPACE`. Also contains the space that would be required.
    InsufficientSpace(usize),
    /// Custom error code to indicate that an optional callback method has not been implemented.
    /// If this is returned from a required callback method, it will bubble up as an `Io` error.
    NotImplemented,
}

/// `Result` type for `IoError` errors.
pub type IoResult<T> = Result<T, IoError>;

impl fmt::Display for IoError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Oom => write!(f, "Unable to allocate memory"),
            Self::Io => write!(f, "I/O error"),
            Self::NoSuchPartition => write!(f, "No such partition exists"),
            Self::RangeOutsidePartition => write!(f, "Range is outside the partition"),
            Self::NoSuchValue => write!(f, "No such named persistent value"),
            Self::InvalidValueSize => write!(f, "Invalid named persistent value size"),
            Self::InsufficientSpace(size) => write!(f, "Buffer is too small (requires {})", size),
            Self::NotImplemented => write!(f, "Function not implemented"),
        }
    }
}

impl From<Utf8Error> for IoError {
    fn from(_: Utf8Error) -> Self {
        Self::Io
    }
}

// Converts our `IoError` to the bindgen `AvbIOResult` enum.
//
// Unlike `SlotVerifyError` which gets generated by libavb and passed to the caller, `IoError` is
// created by the user callbacks and passed back into libavb so we need to be able to convert in
// this direction as well.
impl From<IoError> for AvbIOResult {
    fn from(error: IoError) -> Self {
        match error {
            IoError::Oom => AvbIOResult::AVB_IO_RESULT_ERROR_OOM,
            IoError::Io => AvbIOResult::AVB_IO_RESULT_ERROR_IO,
            IoError::NoSuchPartition => AvbIOResult::AVB_IO_RESULT_ERROR_NO_SUCH_PARTITION,
            IoError::RangeOutsidePartition => {
                AvbIOResult::AVB_IO_RESULT_ERROR_RANGE_OUTSIDE_PARTITION
            }
            IoError::NoSuchValue => AvbIOResult::AVB_IO_RESULT_ERROR_NO_SUCH_VALUE,
            IoError::InvalidValueSize => AvbIOResult::AVB_IO_RESULT_ERROR_INVALID_VALUE_SIZE,
            IoError::InsufficientSpace(_) => AvbIOResult::AVB_IO_RESULT_ERROR_INSUFFICIENT_SPACE,
            // `NotImplemented` is internal to this library and doesn't have a libavb equivalent,
            // convert it to the default I/O error.
            IoError::NotImplemented => AvbIOResult::AVB_IO_RESULT_ERROR_IO,
        }
    }
}

/// Converts an `IoResult<>` to the bindgen `AvbIOResult` enum.
pub(crate) fn result_to_io_enum(result: IoResult<()>) -> AvbIOResult {
    result.map_or_else(|e| e.into(), |_| AvbIOResult::AVB_IO_RESULT_OK)
}

/// Converts a bindgen `AvbIOResult` enum to an `IoResult<>`, mapping `AVB_IO_RESULT_OK` to the Rust
/// equivalent `Ok(())` and errors to the corresponding `Err(IoError)`.
///
/// This function is also important to serve as a compile-time check that we're handling all the
/// libavb enums; if a new one is added to (or removed from) the C code, this will fail to compile
/// until it is updated to match.
pub(crate) fn io_enum_to_result(result: AvbIOResult) -> IoResult<()> {
    match result {
        AvbIOResult::AVB_IO_RESULT_OK => Ok(()),
        AvbIOResult::AVB_IO_RESULT_ERROR_OOM => Err(IoError::Oom),
        AvbIOResult::AVB_IO_RESULT_ERROR_IO => Err(IoError::Io),
        AvbIOResult::AVB_IO_RESULT_ERROR_NO_SUCH_PARTITION => Err(IoError::NoSuchPartition),
        AvbIOResult::AVB_IO_RESULT_ERROR_RANGE_OUTSIDE_PARTITION => {
            Err(IoError::RangeOutsidePartition)
        }
        AvbIOResult::AVB_IO_RESULT_ERROR_NO_SUCH_VALUE => Err(IoError::NoSuchValue),
        AvbIOResult::AVB_IO_RESULT_ERROR_INVALID_VALUE_SIZE => Err(IoError::InvalidValueSize),
        AvbIOResult::AVB_IO_RESULT_ERROR_INSUFFICIENT_SPACE => Err(IoError::InsufficientSpace(0)),
    }
}

/// `AvbVBMetaVerifyResult` error wrapper.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VbmetaVerifyError {
    /// `AVB_VBMETA_VERIFY_RESULT_OK_NOT_SIGNED`
    NotSigned,
    /// `AVB_VBMETA_VERIFY_RESULT_INVALID_VBMETA_HEADER`
    InvalidVbmetaHeader,
    /// `AVB_VBMETA_VERIFY_RESULT_UNSUPPORTED_VERSION`
    UnsupportedVersion,
    /// `AVB_VBMETA_VERIFY_RESULT_HASH_MISMATCH`
    HashMismatch,
    /// `AVB_VBMETA_VERIFY_RESULT_SIGNATURE_MISMATCH`
    SignatureMismatch,
}

/// `Result` type for `VbmetaVerifyError` errors.
pub type VbmetaVerifyResult<T> = Result<T, VbmetaVerifyError>;

impl fmt::Display for VbmetaVerifyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::NotSigned => write!(f, "vbmeta is unsigned"),
            Self::InvalidVbmetaHeader => write!(f, "invalid vbmeta header"),
            Self::UnsupportedVersion => write!(f, "unsupported vbmeta version"),
            Self::HashMismatch => write!(f, "vbmeta hash mismatch"),
            Self::SignatureMismatch => write!(f, "vbmeta signature mismatch"),
        }
    }
}

// Converts a bindgen `AvbVBMetaVerifyResult` enum to a `VbmetaVerifyResult<>`, mapping
// `AVB_VBMETA_VERIFY_RESULT_OK` to the Rust equivalent `Ok(())` and errors to the corresponding
// `Err(SlotVerifyError)`.
//
// This function is also important to serve as a compile-time check that we're handling all the
// libavb enums; if a new one is added to (or removed from) the C code, this will fail to compile
// until it is updated to match.
pub fn vbmeta_verify_enum_to_result(result: AvbVBMetaVerifyResult) -> VbmetaVerifyResult<()> {
    match result {
        AvbVBMetaVerifyResult::AVB_VBMETA_VERIFY_RESULT_OK => Ok(()),
        AvbVBMetaVerifyResult::AVB_VBMETA_VERIFY_RESULT_OK_NOT_SIGNED => {
            Err(VbmetaVerifyError::NotSigned)
        }
        AvbVBMetaVerifyResult::AVB_VBMETA_VERIFY_RESULT_INVALID_VBMETA_HEADER => {
            Err(VbmetaVerifyError::InvalidVbmetaHeader)
        }
        AvbVBMetaVerifyResult::AVB_VBMETA_VERIFY_RESULT_UNSUPPORTED_VERSION => {
            Err(VbmetaVerifyError::UnsupportedVersion)
        }
        AvbVBMetaVerifyResult::AVB_VBMETA_VERIFY_RESULT_HASH_MISMATCH => {
            Err(VbmetaVerifyError::HashMismatch)
        }
        AvbVBMetaVerifyResult::AVB_VBMETA_VERIFY_RESULT_SIGNATURE_MISMATCH => {
            Err(VbmetaVerifyError::SignatureMismatch)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_slot_verify_error() {
        // The actual error message can change as needed, the point of the test is just to make sure
        // the fmt::Display trait is properly implemented.
        assert_eq!(
            format!("{}", SlotVerifyError::Verification(None)),
            "Verification failure"
        );
    }

    #[test]
    fn convert_slot_verify_enum_to_result() {
        assert!(matches!(
            slot_verify_enum_to_result(AvbSlotVerifyResult::AVB_SLOT_VERIFY_RESULT_OK),
            Ok(())
        ));
        assert!(matches!(
            slot_verify_enum_to_result(AvbSlotVerifyResult::AVB_SLOT_VERIFY_RESULT_ERROR_IO),
            Err(SlotVerifyError::Io)
        ));
    }

    #[test]
    fn display_io_error() {
        // The actual error message can change as needed, the point of the test is just to make sure
        // the fmt::Display trait is properly implemented.
        assert_eq!(
            format!("{}", IoError::NoSuchPartition),
            "No such partition exists"
        );
    }

    #[test]
    fn convert_io_enum_to_result() {
        // This is a compile-time check that we handle all the `AvbIOResult` enum values. If any
        // enums are added or removed this will break, indicating we need to update `IoError` to
        // match.
        assert_eq!(io_enum_to_result(AvbIOResult::AVB_IO_RESULT_OK), Ok(()));
        assert_eq!(
            io_enum_to_result(AvbIOResult::AVB_IO_RESULT_ERROR_NO_SUCH_PARTITION),
            Err(IoError::NoSuchPartition)
        );
    }

    #[test]
    fn convert_io_result_to_enum() {
        assert_eq!(result_to_io_enum(Ok(())), AvbIOResult::AVB_IO_RESULT_OK);
        assert_eq!(
            result_to_io_enum(Err(IoError::Io)),
            AvbIOResult::AVB_IO_RESULT_ERROR_IO
        );
    }

    #[test]
    fn display_vmbeta_verify_error() {
        // The actual error message can change as needed, the point of the test is just to make sure
        // the fmt::Display trait is properly implemented.
        assert_eq!(
            format!("{}", VbmetaVerifyError::NotSigned),
            "vbmeta is unsigned"
        );
    }

    #[test]
    fn convert_vbmeta_verify_enum_to_result() {
        assert_eq!(
            vbmeta_verify_enum_to_result(AvbVBMetaVerifyResult::AVB_VBMETA_VERIFY_RESULT_OK),
            Ok(())
        );
        assert_eq!(
            vbmeta_verify_enum_to_result(
                AvbVBMetaVerifyResult::AVB_VBMETA_VERIFY_RESULT_HASH_MISMATCH
            ),
            Err(VbmetaVerifyError::HashMismatch)
        );
    }
}
