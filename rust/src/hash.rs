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

//! libavb_hash support.

use crate::IoResult;

/// `AvbDigestType`; see libavb docs for descriptions of each type.
pub use avb_bindgen::AvbDigestType as HashType;

/// Rust wrapper over libavb `avb_bindgen::AvbHashOps`.
pub trait HashOps {
    /// Initializes a new hashing session using the specified `hash_type`.
    ///
    /// # Arguments
    /// * `hash_type` - The type of hash algorithm to be used (e.g. SHA-256, SHA-512).
    ///
    /// # Errors
    /// Returns an `Err` if the hashing operation could not be initialized.
    fn init(&mut self, hash_type: HashType) -> IoResult<()>;

    /// Updates the ongoing hash computation with the given data.
    ///
    /// # Arguments
    /// * `data` - A slice of bytes to incorporate into the current hash.
    ///
    /// # Errors
    /// Returns an `Err` if processing the data fails for any reason (e.g.,
    /// internal errors in the hashing implementation).
    fn update(&mut self, data: &[u8]) -> IoResult<()>;

    /// Finalizes the hash computation and returns a reference to the computed digest.
    ///
    /// The returned slice must remains valid until the next call to `init`.
    ///
    /// # Errors
    /// Returns an `Err` if the finalization step fails (e.g., if the hashing state is invalid).
    fn finalize(&mut self) -> IoResult<&[u8]>;
}
