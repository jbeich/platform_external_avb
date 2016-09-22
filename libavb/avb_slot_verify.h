/*
 * Copyright (C) 2016 The Android Open Source Project
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

#if !defined(AVB_INSIDE_LIBAVB_H) && !defined(AVB_COMPILATION)
#error "Never include this file directly, include libavb.h instead."
#endif

#ifndef AVB_SLOT_VERIFY_H_
#define AVB_SLOT_VERIFY_H_

#include "avb_ops.h"
#include "avb_vbmeta_image.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Return codes used in avb_slot_verify(), see that function for
 * documentation for each field.
 *
 * Use avb_slot_verify_result_to_string() to get a textual
 * representation usable for error/debug output.
 */
typedef enum {
  AVB_SLOT_VERIFY_RESULT_OK,
  AVB_SLOT_VERIFY_RESULT_ERROR_OOM,
  AVB_SLOT_VERIFY_RESULT_ERROR_IO,
  AVB_SLOT_VERIFY_RESULT_ERROR_VERIFICATION,
  AVB_SLOT_VERIFY_RESULT_ERROR_ROLLBACK_INDEX,
  AVB_SLOT_VERIFY_RESULT_ERROR_PUBLIC_KEY_REJECTED,
  AVB_SLOT_VERIFY_RESULT_ERROR_INVALID_METADATA
} AvbSlotVerifyResult;

/* Get a textual representation of |result|. */
const char* avb_slot_verify_result_to_string(AvbSlotVerifyResult result);

/* Maximum number of rollback index slots number supported. */
#define AVB_MAX_NUMBER_OF_ROLLBACK_INDEX_SLOTS 32

/* AvbSlotVerifyData contains data needed to boot a particular slot
 * and is returned by avb_slot_verify() if partitions in a slot are
 * successfully verified.
 *
 * All data pointed to by this struct will be freed when the
 * avb_slot_verify_data_free() function is called.
 *
 * The |ab_suffix| field is the copy of the of |ab_suffix| field
 * passed to avb_slot_verify(). It is the A/B suffix of the slot.
 *
 * The image loaded and verified from the boot partition of the slot
 * is accessible via the |boot_data| and is of length |boot_size|
 * bytes. Note that this is strictly less than the partition size -
 * it's only the image stored there, not the entire partition nor any
 * of the metadata.
 *
 * The verified vbmeta image in the 'vbmeta' partition of the slot is
 * accessible from the |vbmeta_data| field and is of length
 * |vbmeta_size| bytes. You can use this data with
 * e.g. avb_descriptor_get_all().
 *
 * Rollback indexes for the slot are stored in the |rollback_indexes|
 * field.
 *
 * The |cmdline| field is a NUL-terminated string in UTF-8 resulting
 * from concatenating all |AvbKernelCmdlineDescriptor| and then
 * performing proper substitution of the variables
 * $(ANDROID_SYSTEM_PARTUUID) and $(ANDROID_BOOT_PARTUUID) using the
 * get_unique_guid_for_partition() operation in |AvbOps|.
 *
 * Additionally, the |cmdline| field will have the following kernel
 * command-line options set:
 *
 *   androidboot.avb.device_state: set to "locked" or "unlocked"
 *   depending on the result of the result of AvbOps's
 *   read_is_unlocked() function.
 *
 *   androidboot.slot_suffix: If |ab_suffix| as passed into
 *   avb_slot_verify() is non-empty, this variable will be set to its
 *   value.
 *
 *   androidboot.vbmeta.{hash_alg, size, digest}: Will be set to
 *   the digest of the vbmeta image.
 */
typedef struct {
  char* ab_suffix;
  uint8_t* boot_data;
  size_t boot_size;
  uint8_t* vbmeta_data;
  size_t vbmeta_size;
  char* cmdline;
  uint64_t rollback_indexes[AVB_MAX_NUMBER_OF_ROLLBACK_INDEX_SLOTS];
} AvbSlotVerifyData;

/* Frees a |AvbSlotVerifyData| including all data it points to. */
void avb_slot_verify_data_free(AvbSlotVerifyData* data);

/* Performs a full verification of the slot identified by
 * |ab_suffix|. If not using A/B, pass an empty string (e.g. "", not
 * NULL) for |ab_suffix|.
 *
 * This includes loading data from the 'vbmeta', 'boot', and possibly
 * other partitions (with |ab_suffix| appended), inspecting rollback
 * indexes, and checking if the public key used to sign the data is
 * acceptable. The functions in |ops| will be used to do this.
 *
 * If |out_data| is not NULL, it will be set to a newly allocated
 * |AvbSlotVerifyData| struct containing all the data needed to
 * actually boot the slot. This data structure should be freed with
 * avb_slot_verify_data_free() when you are done with it.
 *
 * AVB_SLOT_VERIFY_RESULT_OK is returned if everything is verified
 * correctly and all public keys are accepted.
 *
 * AVB_SLOT_VERIFY_RESULT_ERROR_PUBLIC_KEY_REJECTED is returned if
 * everything is verified correctly out but one or more public keys
 * are not accepted. This includes the case where integrity data is
 * not signed.
 *
 * AVB_SLOT_VERIFY_RESULT_ERROR_OOM is returned if unable to
 * allocate memory.
 *
 * AVB_SLOT_VERIFY_RESULT_ERROR_IO is returned if an I/O error
 * occurred while trying to load data or get a rollback index.
 *
 * AVB_SLOT_VERIFY_RESULT_ERROR_VERIFICATION is returned if the data
 * did not verify, e.g. the digest didn't match or signature checks
 * failed.
 *
 * AVB_SLOT_VERIFY_RESULT_ERROR_ROLLBACK_INDEX is returned if a
 * rollback index was less than its stored value.
 *
 * AVB_SLOT_VERIFY_RESULT_ERROR_INVALID_METADATA is returned if some
 * of the metadata is invalid or inconsistent.
 */
AvbSlotVerifyResult avb_slot_verify(AvbOps* ops, const char* ab_suffix,
                                    AvbSlotVerifyData** out_data);

#ifdef __cplusplus
}
#endif

#endif /* AVB_SLOT_VERIFY_H_ */
