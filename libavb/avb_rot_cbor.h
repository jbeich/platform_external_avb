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

#ifndef AVB_ROT_CBOR_H
#define AVB_ROT_CBOR_H

#include "avb_sysdeps.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAJOR_TYPE_MASK 0x07
// Mask for additional information in the low-order 5 bits
#define ADDINFO_MASK 0x1F
// Major type 0: an unsigned integer
#define TYPE_UNSIGNED_INTEGER 0x00
// Major type 1: a negative integer
#define TYPE_NEGATIVE_INTEGER 0x01
// Major type 2: a byte string
#define TYPE_BYTE_STRING 0x02
// Major type 3: a text string
#define TYPE_TEXT_STRING 0x03
// Major type 4: an array of data items
#define TYPE_ARRAY 0x04
// Major type 5: a map of pairs of data items
#define TYPE_MAP 0x05
// Major type 6: optional semantic tagging of other major types
#define TYPE_TAG 0x06
// Major type 7: floating-point numbers
#define TYPE_FLOAT 0x07
/**
 * Length information (Integer size, array length, etc.) in low-order 5 bits
 */
// One byte unsigned value (uint8)
#define ENCODED_ONE_BYTE 0x18
// Two byte unsigned value (uint16)
#define ENCODED_TWO_BYTES 0x19
// Four byte unsigned value (uint32)
#define ENCODED_FOUR_BYTES 0x1a
// Eight byte unsigned value (uint64)
#define ENCODED_EIGHT_BYTES 0x1b

/**
 * Values for additional information in major type 7
 */
// CBOR encoded boolean - false
#define ENCODED_FALSE 0xF4
// CBOR encoded boolean - true
#define ENCODED_TRUE 0xF5
// CBOR encoded null
#define ENCODED_NULL 0xF6
// CBOR encoded undefined value
#define ENCODED_UNDEFINED 0xF7

// CBOR encoded break for unlimited arrays/maps.
#define ENCODED_BREAK 0xFF

#define ERR_OOB false
#define ERR_OK true

// Used by avb rot cbor error handling
#define avb_rot_cbor_error(expr, lbl) \
  do {                                \
    if (!(expr)) {                    \
      goto lbl;                       \
    }                                 \
  } while (0)

// Used by avb rot cbor functions
typedef struct {
  uint8_t* buf;
  uint16_t cur;
  uint16_t end;
} CborCtx;

void avb_rot_cbor_increase_offset(CborCtx* ctx, uint16_t inc);

bool avb_rot_cbor_is_out_of_bounds(CborCtx* ctx, uint16_t inc);

bool avb_rot_cbor_write_uint_as_array(CborCtx* ctx,
                                      uint8_t* value,
                                      size_t size);

bool avb_rot_cbor_write_raw_byte(CborCtx* ctx, uint8_t val);

bool avb_rot_cbor_write_uint8(CborCtx* ctx, uint8_t type, uint8_t value);
bool avb_rot_cbor_write_uint16(CborCtx* ctx, uint8_t type, uint16_t value);

bool avb_rot_cbor_write_uint32(CborCtx* ctx, uint8_t type, uint32_t value);
bool avb_rot_cbor_write_uint64(CborCtx* ctx, uint8_t type, uint64_t value);

bool avb_rot_cbor_write_raw_byte_as_array(CborCtx* ctx,
                                          const uint8_t* value,
                                          short offset,
                                          short length);
bool avb_rot_cbor_encode_boolean(CborCtx* ctx, bool value);

bool avb_rot_cbor_encode_value(CborCtx* ctx, uint8_t majorType, uint64_t value);

bool avb_rot_cbor_encode_byte_string(CborCtx* ctx,
                                     const uint8_t* byteString,
                                     short offset,
                                     short length);

bool avb_rot_cbor_encode_text_string(CborCtx* ctx,
                                     const uint8_t* textString,
                                     short offset,
                                     short length);

bool avb_rot_cbor_encode_uint(CborCtx* ctx, uint64_t val);

bool avb_rot_cbor_encode_neg_int(CborCtx* ctx, int64_t val);

bool avb_rot_cbor_start_array(CborCtx* ctx, short arraySize);

bool avb_rot_cbor_start_map(CborCtx* ctx, short mapSize);

#ifdef __cplusplus
}
#endif

#endif
