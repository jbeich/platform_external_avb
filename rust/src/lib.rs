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

//! Rust libavb.
//!
//! This library wraps the libavb C code with safe Rust APIs. This does not materially affect the
//! safety of the library itself, since the internal implementation is still C. The goal here is
//! instead to provide a simple way to use libavb from Rust, in order to make Rust a more
//! appealing option for code that may want to use libavb such as bootloaders.
//!
//! This library is [no_std] for portability.

#![cfg_attr(not(test), no_std)]

mod error;
mod verify;

pub use error::{IoError, SlotVerifyError};
pub use verify::Ops;

/// APIs that will eventually be internal-only to this library, but while this library is split need
/// to be exposed externally.
//
// TODO(b/290110273): remove this module once we've moved the full libavb wrapper here.
pub mod internal {
    use super::*;

    pub use error::{result_to_io_enum, slot_verify_enum_to_result};
}
