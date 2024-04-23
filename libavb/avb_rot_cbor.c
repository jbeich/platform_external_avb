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

#include "avb_rot_cbor.h"

#include "avb_sysdeps.h"
#include "avb_util.h"

// static uint8_t avb_rot_cbor_get_raw_byte(const CborCtx* ctx) {
//  return ctx->buf[ctx->cur];
//}

void avb_rot_cbor_increase_offset(CborCtx* ctx, uint16_t inc) {
  ctx->cur += inc;
}

bool avb_rot_cbor_is_out_of_bounds(CborCtx* ctx, uint16_t inc) {
  return (inc + ctx->cur) >= ctx->end;
}

// Android is little endian - so add the number in reverse
bool avb_rot_cbor_write_uint_as_array(CborCtx* ctx,
                                      uint8_t* value,
                                      size_t size) {
  if (avb_rot_cbor_is_out_of_bounds(ctx, size)) {
    return ERR_OOB;
  }
  for (size_t i = size; i > 0; i--) {
    ctx->buf[ctx->cur] = value[i - 1];
    avb_rot_cbor_increase_offset(ctx, 1);
  }
  return ERR_OK;
}
bool avb_rot_cbor_write_raw_byte(CborCtx* ctx, uint8_t val) {
  if (avb_rot_cbor_is_out_of_bounds(ctx, 1)) {
    return ERR_OOB;
  }
  ctx->buf[ctx->cur] = val;
  avb_rot_cbor_increase_offset(ctx, 1);
  return ERR_OK;
}
bool avb_rot_cbor_write_uint8(CborCtx* ctx, uint8_t type, uint8_t value) {
  if (avb_rot_cbor_is_out_of_bounds(ctx, 2)) return ERR_OOB;
  avb_rot_cbor_write_raw_byte(ctx, (uint8_t)(type | ENCODED_ONE_BYTE));
  avb_rot_cbor_write_raw_byte(ctx, value);
  return ERR_OK;
}

bool avb_rot_cbor_write_uint16(CborCtx* ctx, uint8_t type, uint16_t value) {
  if (avb_rot_cbor_is_out_of_bounds(ctx, 3)) {
    return ERR_OOB;
  }
  avb_rot_cbor_write_raw_byte(ctx, (uint8_t)(type | ENCODED_TWO_BYTES));
  avb_rot_cbor_write_uint_as_array(ctx, (uint8_t*)&value, 2);
  return ERR_OK;
}

bool avb_rot_cbor_write_uint32(CborCtx* ctx, uint8_t type, uint32_t value) {
  if (avb_rot_cbor_is_out_of_bounds(ctx, 5)) {
    return ERR_OOB;
  }
  avb_rot_cbor_write_raw_byte(ctx, (uint8_t)(type | ENCODED_FOUR_BYTES));
  avb_rot_cbor_write_uint_as_array(ctx, (uint8_t*)&value, 4);
  return ERR_OK;
}

bool avb_rot_cbor_write_uint64(CborCtx* ctx, uint8_t type, uint64_t value) {
  if (avb_rot_cbor_is_out_of_bounds(ctx, 9)) {
    return ERR_OOB;
  }
  avb_rot_cbor_write_raw_byte(ctx, (uint8_t)(type | ENCODED_EIGHT_BYTES));
  avb_rot_cbor_write_uint_as_array(ctx, (uint8_t*)&value, 8);
  return ERR_OK;
}

bool avb_rot_cbor_write_raw_byte_as_array(CborCtx* ctx,
                                          const uint8_t* value,
                                          short offset,
                                          short length) {
  if (avb_rot_cbor_is_out_of_bounds(ctx, length)) {
    return ERR_OOB;
  }
  value += offset;
  avb_memcpy((ctx->buf + ctx->cur), value, length);
  avb_rot_cbor_increase_offset(ctx, length);
  return ERR_OK;
}

bool avb_rot_cbor_encode_boolean(CborCtx* ctx, bool value) {
  if (value) {
    return avb_rot_cbor_write_raw_byte(ctx, ENCODED_TRUE);
  } else {
    return avb_rot_cbor_write_raw_byte(ctx, ENCODED_FALSE);
  }
}

// static bool avb_rot_cbor_encode_raw_data(CborCtx* ctx,
//     external/avb/libavb/avb-crypto/curve25519/avb_curve25519.c const uint8_t*
//     value,
//                                          short offset,
//                                          short length) {
//   return avb_rot_cbor_write_raw_byte_as_array(ctx, value, offset, length);
// }

bool avb_rot_cbor_encode_value(CborCtx* ctx,
                               uint8_t majorType,
                               uint64_t value) {
  if (value < ENCODED_ONE_BYTE) {
    return avb_rot_cbor_write_raw_byte(ctx, majorType | value);
  } else if (value < 0x100) {
    return avb_rot_cbor_write_uint8(ctx, majorType, value);
  } else if (value < 0x10000) {
    return avb_rot_cbor_write_uint16(ctx, majorType, value);
  } else if (value < 0x100000000) {
    return avb_rot_cbor_write_uint32(ctx, majorType, value);
  } else {
    return avb_rot_cbor_write_uint64(ctx, majorType, value);
  }
}
bool avb_rot_cbor_encode_byte_string(CborCtx* ctx,
                                     const uint8_t* byteString,
                                     short offset,
                                     short length) {
  if (!avb_rot_cbor_encode_value(
          ctx, (uint8_t)(TYPE_BYTE_STRING << 5), length)) {
    return ERR_OOB;
  }
  return avb_rot_cbor_write_raw_byte_as_array(ctx, byteString, offset, length);
}

bool avb_rot_cbor_encode_text_string(CborCtx* ctx,
                                     const uint8_t* textString,
                                     short offset,
                                     short length) {
  if (!avb_rot_cbor_encode_value(
          ctx, (uint8_t)(TYPE_TEXT_STRING << 5), length)) {
    return ERR_OOB;
  }
  return avb_rot_cbor_write_raw_byte_as_array(ctx, textString, offset, length);
}

bool avb_rot_cbor_encode_uint(CborCtx* ctx, uint64_t val) {
  return avb_rot_cbor_encode_value(
      ctx, (uint8_t)(TYPE_UNSIGNED_INTEGER << 5), val);
}
bool avb_rot_cbor_encode_neg_int(CborCtx* ctx, int64_t val) {
  return avb_rot_cbor_encode_value(
      ctx, (uint8_t)(TYPE_NEGATIVE_INTEGER << 5), (-1 - val));
}
// static bool avb_rot_cbor_encode_tag(CborCtx* ctx, uint8_t value) {
//    return avb_rot_cbor_encode_value(ctx, (uint8_t)(TYPE_TAG << 5), value);
//  }
bool avb_rot_cbor_start_array(CborCtx* ctx, short arraySize) {
  return avb_rot_cbor_encode_value(ctx, (uint8_t)(TYPE_ARRAY << 5), arraySize);
}

bool avb_rot_cbor_start_map(CborCtx* ctx, short mapSize) {
  return avb_rot_cbor_encode_value(ctx, (uint8_t)(TYPE_MAP << 5), mapSize);
}

// static bool avb_rot_cbor_start_byte_string(CborCtx* ctx, short length) {
//   return avb_rot_cbor_encode_value(
//       ctx, (uint8_t)(TYPE_BYTE_STRING << 5), length);
// }

// static bool avb_rot_cbor_start_text_string(CborCtx* ctx, short length) {
//   return avb_rot_cbor_encode_value(
//       ctx, (uint8_t)(TYPE_TEXT_STRING << 5), length);
// }
