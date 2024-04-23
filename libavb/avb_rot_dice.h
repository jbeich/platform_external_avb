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

#ifndef AVB_ROT_DICE_H
#define AVB_ROT_DICE_H

#include "avb_ed25519.h"

#define AVB_ROT_DICE_PRIVATE_KEY_LEN 64
#define AVB_ROT_DICE_PUBLIC_KEY_LEN 32
#define AVB_ROT_DICE_SIGNATURE_LEN 64
#ifdef __cplusplus
extern "C" {
#endif

bool avb_rot_dice_generate_certificate(
    const uint8_t subject_public_key[AVB_ROT_DICE_PUBLIC_KEY_LEN],
    const char* cert_subject,
    const uint8_t authority_public_key[AVB_ROT_DICE_PUBLIC_KEY_LEN],
    const uint8_t authority_private_key[AVB_ROT_DICE_PRIVATE_KEY_LEN],
    size_t certificate_buffer_size,
    uint8_t* certificate,
    size_t* certificate_actual_size);

#ifdef __cplusplus
}
#endif

#endif
