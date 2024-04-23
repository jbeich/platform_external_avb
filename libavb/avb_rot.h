/*
 * Copyright 2024 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifdef AVB_INSIDE_LIBAVB_H
#error "You can't include avb_rot.h in the public header libavb.h."
#endif

#ifndef AVB_COMPILATION
#error "Never include this file, it may only be used from internal avb code."
#endif

#ifndef AVB_ROT_H
#define AVB_ROT_H

#include "avb_crypto_ops_impl.h"
#include "avb_slot_verify.h"

#ifdef __cplusplus
extern "C" {
#endif

#define AVB_ROT_MAX_SIGNING_KEY_CERT_SIZE 512
#define AVB_ROT_MAX_DATA_SIZE 512

AvbSlotVerifyResult avb_rot_generate_rot_data(AvbOps* ops,
                                              AvbSlotVerifyData* slotData);

#ifdef __cplusplus
}
#endif

#endif
