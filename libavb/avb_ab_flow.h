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

#ifndef AVB_AB_FLOW_H_
#define AVB_AB_FLOW_H_

#include "avb_ops.h"
#include "avb_slot_verify.h"
#include "avb_vbmeta_image.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Magic for the A/B struct when serialized. */
#define AVB_AB_MAGIC "\0AB0"
#define AVB_AB_MAGIC_LEN 4

/* Versioning for the on-disk A/B metadata - keep in sync with avbtool. */
#define AVB_AB_MAJOR_VERSION 1
#define AVB_AB_MINOR_VERSION 0

/* Size of AvbABData struct. */
#define AVB_AB_DATA_SIZE 32

/* Maximum values for slot data */
#define AVB_AB_MAX_PRIORITY 15
#define AVB_AB_MAX_TRIES_REMAINING 7

/* Struct used for recording per-slot metadata.
 *
 * When serialized, data is stored in network byte-order.
 */
typedef struct AvbABSlotData {
  /* Slot priority. Valid values range from 0 to AVB_AB_MAX_PRIORITY,
   * both inclusive with 1 being the lowest and AVB_AB_MAX_PRIORITY
   * being the highest. The special value 0 is used to indicate the
   * slot is unbootable.
   */
  uint8_t priority;

  /* Number of times left attempting to boot this slot ranging from 0
   * to AVB_AB_MAX_TRIES_REMAINING.
   */
  uint8_t tries_remaining;

  /* Non-zero if this slot has booted successfully, 0 otherwise. */
  uint8_t successful_boot;

  /* Reserved for future use. */
  uint8_t reserved[1];
} AVB_ATTR_PACKED AvbABSlotData;

/* Struct used for recording A/B metadata.
 *
 * When serialized, data is stored in network byte-order.
 */
typedef struct AvbABData {
  /* Magic number used for identification - see AVB_AB_MAGIC. */
  uint8_t magic[AVB_AB_MAGIC_LEN];

  /* Version of on-disk struct - see AVB_AB_{MAJOR,MINOR}_VERSION. */
  uint8_t version_major;
  uint8_t version_minor;

  /* Padding to ensure |slots| field start eight bytes in. */
  uint8_t reserved1[2];

  /* Per-slot metadata. */
  AvbABSlotData slots[2];

  /* Reserved for future use. */
  uint8_t reserved2[12];

  /* CRC32 of all 28 bytes preceding this field. */
  uint32_t crc32;
} AVB_ATTR_PACKED AvbABData;

/* Copies |src| to |dest|, byte-swapping fields in the
 * process. Returns false if the data is invalid (e.g. wrong magic,
 * wrong CRC32 etc.), true otherwise.
 */
bool avb_ab_data_verify_and_byteswap(const AvbABData* src, AvbABData* dest);

/* Copies |src| to |dest|, byte-swapping fields in the process. Also
 * updates the |crc32| field in |dest|.
 */
void avb_ab_data_update_crc_and_byteswap(const AvbABData* src, AvbABData* dest);

/* Initializes |data| such that it has two slots and both slots have
 * maximum tries remaining. The CRC is not set.
 */
void avb_ab_data_init(AvbABData* data);

/* Reads A/B metadata from the 'misc' partition using |ops|. Returned
 * data is properly byteswapped. Returns false if an I/O operation
 * failed.
 *
 * If the data read from disk is invalid (e.g. wrong magic or CRC
 * checksum failure), the metadata will be reset using
 * avb_ab_data_init() and then written to disk.
 */
bool avb_ab_data_read(AvbOps* ops, AvbABData* data);

/* Writes A/B metadata to the 'misc' partition using |ops|. This will
 * byteswap and update the CRC as needed. Returns false if an I/O
 * error occurs, true otherwise.
 */
bool avb_ab_data_write(AvbOps* ops, const AvbABData* data);

/* Return codes used in avb_ab_flow(), see that function for
 * documentation of each value.
 */
typedef enum {
  AVB_AB_FLOW_RESULT_OK,
  AVB_AB_FLOW_RESULT_ERROR_OOM,
  AVB_AB_FLOW_RESULT_ERROR_IO,
  AVB_AB_FLOW_RESULT_ERROR_NO_BOOTABLE_SLOTS
} AvbABFlowResult;

/* High-level function to select a slot to boot. The following
 * algorithm is used:
 *
 * 1. A/B metadata is loaded and validated from the 'misc' partition.
 * If the metadata on disk is invalid, it is reset using
 * avb_ab_data_init(), written to disk, and then returned.
 *
 * 2. All bootable slots listed in the A/B metadata are verified using
 * avb_slot_verify(). If a slot fails verification, it will be marked
 * as unbootable in the A/B metadata and the metadata will be saved to
 * disk before returning.
 *
 * 3. If there are no bootable slots, the value
 * AVB_AB_FLOW_RESULT_ERROR_NO_BOOTABLE_SLOTS is returned.
 *
 * 4. For each bootable slot, the Stored Rollback Indexes are updated
 * such that for each rollback index slot, the Stored Rollback Index
 * is the largest number smaller than or equal to the Rollback Index
 * of each slot.
 *
 * 5. The bootable slot with the highest priority is selected and
 * returned in |out_data|. If this slot is already marked as
 * successful, the A/B metadata is not modified. However, if the slot
 * is not marked as bootable its |tries_remaining| count is
 * decremented and the A/B metadata is saved to disk before returning.
 * In either case the value AVB_AB_FLOW_RESULT_OK is returning.
 *
 * If an I/O operation - such as loading/saving metadata or checking
 * rollback indexes - fail, the value AVB_AB_FLOW_RESULT_ERROR_IO is
 * returned.
 *
 * If memory allocation fails, AVB_AB_FLOW_RESULT_ERROR_OOM is
 * returned.
 *
 * Reasonable behavior for handling AVB_AB_FLOW_RESULT_ERROR_NO_BOOTABLE_SLOTS
 * is to initiate device recovery (which is device-dependent).
 */
AvbABFlowResult avb_ab_flow(AvbOps* ops, AvbSlotVerifyData** out_data);

/* Marks the slot with the given slot number as active. Returns false
 * if the operation fails.
 *
 * This function is typically used by the OS updater when completing
 * an update. It can also used by the firmware for implementing the
 * "set_active" command.
 */
bool avb_ab_mark_slot_active(AvbOps* ops, unsigned int slot_number);

/* Marks the slot with the given slot number as unbootable. Returns
 * false if the operation fails.
 *
 * This function is typically used by the OS updater before writing to
 * a slot.
 */
bool avb_ab_mark_slot_unbootable(AvbOps* ops, unsigned int slot_number);

/* Marks the slot with the given slot number as having booted
 * successfully. This has no effect is the slot is not
 * bootable. Returns false if the operation fails.
 *
 * This function is typically used by the OS updater after having
 * confirmed that the slot works as intended.
 */
bool avb_ab_mark_slot_successful(AvbOps* ops, unsigned int slot_number);

#ifdef __cplusplus
}
#endif

#endif /* AVB_AB_FLOW_H_ */
