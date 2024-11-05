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

//! libavb_hash suppor.

use crate::{IoResult};

/// libavb_cert extension callbacks.
pub trait HashOps {
    /// init
    fn init(&mut self) -> IoResult<()>;

    /// update
    fn update(&mut self, data: &[u8]) -> IoResult<()>;

    /// final
    fn finalize(&mut self) -> IoResult<&[u8]>;
}
