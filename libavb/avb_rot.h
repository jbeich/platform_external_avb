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

#define ROT_SIGNING_KEY_CERT_SIZE 512
#define AVB_ROT_MAX_DATA_SIZE 512

AvbSlotVerifyResult avb_rot_generate_rot_data(AvbOps* ops,
                                              AvbSlotVerifyData* slotData);

bool avb_rot_dice_generate_certificate(
    const uint8_t subject_public_key[ED25519_PUBLIC_KEY_LEN],
    const char* cert_subject,
    const uint8_t authority_public_key[ED25519_PUBLIC_KEY_LEN],
    const uint8_t authority_private_key[ED25519_PRIVATE_KEY_LEN],
    size_t certificate_buffer_size,
    uint8_t* certificate,
    size_t* certificate_actual_size);

bool avb_rot_dice_derive_cert_id(const uint8_t* cdi_public_key,
                                 size_t cdi_public_key_size,
                                 uint8_t* id,
                                 size_t id_size);

#ifdef __cplusplus
}
#endif

#endif
