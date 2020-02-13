/*
 * Copyright (C) 2020 The Android Open Source Project
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#if !defined(AVB_INSIDE_LIBAVB_AFTL_H) && !defined(AVB_COMPILATION)
#error "Never include this file directly, include libavb_aftl.h instead."
#endif

#ifndef AVB_AFTL_VERIFY_H_
#define AVB_AFTL_VERIFY_H_

#ifdef __cplusplus
extern "C" {
#endif
/* still need avb_aftl_slot_verify, take params from avb_slot_verify &
   call find_aftl_descriptor and avb_aftl_verify_descriptor on them */
// this probably should move to libavb_aftl.h as it is the public function
AvbSlotVerifyResult aftl_slot_verify(AvbSlotVerifyData* asv_data,
                                     uint8_t* key_bytes,
                                     size_t key_size);

uint8_t* avb_aftl_find_aftl_descriptor(uint8_t* vbmeta_blob,
                                       size_t* vbmeta_size);

/* look at the flow in the readme and match that with error codes*/
AvbSlotVerifyResult avb_aftl_verify_descriptor(uint8_t* cur_vbmeta_data,
                                               size_t cur_vbmeta_size,
                                               uint8_t* aftl_blob,
                                               size_t aftl_size,
                                               uint8_t* key_bytes,
                                               size_t key_num_bytes);

#ifdef __cplusplus
}
#endif

#endif /* AVB_AFTL_VERIFY_H_ */
