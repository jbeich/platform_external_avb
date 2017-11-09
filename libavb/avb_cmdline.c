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

#include "avb_cmdline.h"
#include "avb_sha.h"
#include "avb_util.h"
#include "avb_version.h"

#define NUM_GUIDS 3

/* Substitutes all variables (e.g. $(ANDROID_SYSTEM_PARTUUID)) with
 * values. Returns NULL on OOM, otherwise the cmdline with values
 * replaced.
 */
char* sub_cmdline(AvbOps* ops, const char* cmdline, const char* ab_suffix,
                  bool using_boot_for_vbmeta) {
  const char* part_name_str[NUM_GUIDS] = {"system", "boot", "vbmeta"};
  const char* replace_str[NUM_GUIDS] = {"$(ANDROID_SYSTEM_PARTUUID)",
                                        "$(ANDROID_BOOT_PARTUUID)",
                                        "$(ANDROID_VBMETA_PARTUUID)"};
  char* ret = NULL;
  AvbIOResult io_ret;

  /* Special-case for when the top-level vbmeta struct is in the boot
   * partition.
   */
  if (using_boot_for_vbmeta) {
    part_name_str[2] = "boot";
  }

  /* Replace unique partition GUIDs */
  for (size_t n = 0; n < NUM_GUIDS; n++) {
    char part_name[PART_NAME_MAX_SIZE];
    char guid_buf[37];

    if (!avb_str_concat(part_name,
                        sizeof part_name,
                        part_name_str[n],
                        avb_strlen(part_name_str[n]),
                        ab_suffix,
                        avb_strlen(ab_suffix))) {
      avb_error("Partition name and suffix does not fit.\n");
      goto fail;
    }

    io_ret = ops->get_unique_guid_for_partition(
        ops, part_name, guid_buf, sizeof guid_buf);
    if (io_ret == AVB_IO_RESULT_ERROR_OOM) {
      return NULL;
    } else if (io_ret != AVB_IO_RESULT_OK) {
      avb_error("Error getting unique GUID for partition.\n");
      goto fail;
    }

    if (ret == NULL) {
      ret = avb_replace(cmdline, replace_str[n], guid_buf);
    } else {
      char* new_ret = avb_replace(ret, replace_str[n], guid_buf);
      avb_free(ret);
      ret = new_ret;
    }
    if (ret == NULL) {
      goto fail;
    }
  }

  return ret;

fail:
  if (ret != NULL) {
    avb_free(ret);
  }
  return NULL;
}

static int cmdline_append_option(AvbSlotVerifyData* slot_data,
                                 const char* key,
                                 const char* value) {
  size_t offset, key_len, value_len;
  char* new_cmdline;

  key_len = avb_strlen(key);
  value_len = avb_strlen(value);

  offset = 0;
  if (slot_data->cmdline != NULL) {
    offset = avb_strlen(slot_data->cmdline);
    if (offset > 0) {
      offset += 1;
    }
  }

  new_cmdline = avb_calloc(offset + key_len + value_len + 2);
  if (new_cmdline == NULL) {
    return 0;
  }
  if (offset > 0) {
    avb_memcpy(new_cmdline, slot_data->cmdline, offset - 1);
    new_cmdline[offset - 1] = ' ';
  }
  avb_memcpy(new_cmdline + offset, key, key_len);
  new_cmdline[offset + key_len] = '=';
  avb_memcpy(new_cmdline + offset + key_len + 1, value, value_len);
  if (slot_data->cmdline != NULL) {
    avb_free(slot_data->cmdline);
  }
  slot_data->cmdline = new_cmdline;

  return 1;
}

#define AVB_MAX_DIGITS_UINT64 32

/* Writes |value| to |digits| in base 10 followed by a NUL byte.
 * Returns number of characters written excluding the NUL byte.
 */
static size_t uint64_to_base10(uint64_t value,
                               char digits[AVB_MAX_DIGITS_UINT64]) {
  char rev_digits[AVB_MAX_DIGITS_UINT64];
  size_t n, num_digits;

  for (num_digits = 0; num_digits < AVB_MAX_DIGITS_UINT64 - 1;) {
    rev_digits[num_digits++] = avb_div_by_10(&value) + '0';
    if (value == 0) {
      break;
    }
  }

  for (n = 0; n < num_digits; n++) {
    digits[n] = rev_digits[num_digits - 1 - n];
  }
  digits[n] = '\0';
  return n;
}

static int cmdline_append_version(AvbSlotVerifyData* slot_data,
                                  const char* key,
                                  uint64_t major_version,
                                  uint64_t minor_version) {
  char major_digits[AVB_MAX_DIGITS_UINT64];
  char minor_digits[AVB_MAX_DIGITS_UINT64];
  char combined[AVB_MAX_DIGITS_UINT64 * 2 + 1];
  size_t num_major_digits, num_minor_digits;

  num_major_digits = uint64_to_base10(major_version, major_digits);
  num_minor_digits = uint64_to_base10(minor_version, minor_digits);
  avb_memcpy(combined, major_digits, num_major_digits);
  combined[num_major_digits] = '.';
  avb_memcpy(combined + num_major_digits + 1, minor_digits, num_minor_digits);
  combined[num_major_digits + 1 + num_minor_digits] = '\0';

  return cmdline_append_option(slot_data, key, combined);
}

static int cmdline_append_uint64_base10(AvbSlotVerifyData* slot_data,
                                        const char* key,
                                        uint64_t value) {
  char digits[AVB_MAX_DIGITS_UINT64];
  uint64_to_base10(value, digits);
  return cmdline_append_option(slot_data, key, digits);
}

static int cmdline_append_hex(AvbSlotVerifyData* slot_data,
                              const char* key,
                              const uint8_t* data,
                              size_t data_len) {
  char hex_digits[17] = "0123456789abcdef";
  char* hex_data;
  int ret;
  size_t n;

  hex_data = avb_malloc(data_len * 2 + 1);
  if (hex_data == NULL) {
    return 0;
  }

  for (n = 0; n < data_len; n++) {
    hex_data[n * 2] = hex_digits[data[n] >> 4];
    hex_data[n * 2 + 1] = hex_digits[data[n] & 0x0f];
  }
  hex_data[n * 2] = '\0';

  ret = cmdline_append_option(slot_data, key, hex_data);
  avb_free(hex_data);
  return ret;
}

AvbSlotVerifyResult append_options(
    AvbOps* ops,
    AvbSlotVerifyData* slot_data,
    AvbVBMetaImageHeader* toplevel_vbmeta,
    AvbAlgorithmType algorithm_type,
    AvbHashtreeErrorMode hashtree_error_mode) {
  AvbSlotVerifyResult ret;
  const char* verity_mode;
  bool is_device_unlocked;
  AvbIOResult io_ret;

  /* Add androidboot.vbmeta.device option. */
  if (!cmdline_append_option(slot_data,
                             "androidboot.vbmeta.device",
                             "PARTUUID=$(ANDROID_VBMETA_PARTUUID)")) {
    ret = AVB_SLOT_VERIFY_RESULT_ERROR_OOM;
    goto out;
  }

  /* Add androidboot.vbmeta.avb_version option. */
  if (!cmdline_append_version(slot_data,
                              "androidboot.vbmeta.avb_version",
                              AVB_VERSION_MAJOR,
                              AVB_VERSION_MINOR)) {
    ret = AVB_SLOT_VERIFY_RESULT_ERROR_OOM;
    goto out;
  }

  /* Set androidboot.avb.device_state to "locked" or "unlocked". */
  io_ret = ops->read_is_device_unlocked(ops, &is_device_unlocked);
  if (io_ret == AVB_IO_RESULT_ERROR_OOM) {
    ret = AVB_SLOT_VERIFY_RESULT_ERROR_OOM;
    goto out;
  } else if (io_ret != AVB_IO_RESULT_OK) {
    avb_error("Error getting device state.\n");
    ret = AVB_SLOT_VERIFY_RESULT_ERROR_IO;
    goto out;
  }
  if (!cmdline_append_option(slot_data,
                             "androidboot.vbmeta.device_state",
                             is_device_unlocked ? "unlocked" : "locked")) {
    ret = AVB_SLOT_VERIFY_RESULT_ERROR_OOM;
    goto out;
  }

  /* Set androidboot.vbmeta.{hash_alg, size, digest} - use same hash
   * function as is used to sign vbmeta.
   */
  switch (algorithm_type) {
    /* Explicit fallthrough. */
    case AVB_ALGORITHM_TYPE_NONE:
    case AVB_ALGORITHM_TYPE_SHA256_RSA2048:
    case AVB_ALGORITHM_TYPE_SHA256_RSA4096:
    case AVB_ALGORITHM_TYPE_SHA256_RSA8192: {
      AvbSHA256Ctx ctx;
      size_t n, total_size = 0;
      avb_sha256_init(&ctx);
      for (n = 0; n < slot_data->num_vbmeta_images; n++) {
        avb_sha256_update(&ctx,
                          slot_data->vbmeta_images[n].vbmeta_data,
                          slot_data->vbmeta_images[n].vbmeta_size);
        total_size += slot_data->vbmeta_images[n].vbmeta_size;
      }
      if (!cmdline_append_option(
              slot_data, "androidboot.vbmeta.hash_alg", "sha256") ||
          !cmdline_append_uint64_base10(
              slot_data, "androidboot.vbmeta.size", total_size) ||
          !cmdline_append_hex(slot_data,
                              "androidboot.vbmeta.digest",
                              avb_sha256_final(&ctx),
                              AVB_SHA256_DIGEST_SIZE)) {
        ret = AVB_SLOT_VERIFY_RESULT_ERROR_OOM;
        goto out;
      }
    } break;
    /* Explicit fallthrough. */
    case AVB_ALGORITHM_TYPE_SHA512_RSA2048:
    case AVB_ALGORITHM_TYPE_SHA512_RSA4096:
    case AVB_ALGORITHM_TYPE_SHA512_RSA8192: {
      AvbSHA512Ctx ctx;
      size_t n, total_size = 0;
      avb_sha512_init(&ctx);
      for (n = 0; n < slot_data->num_vbmeta_images; n++) {
        avb_sha512_update(&ctx,
                          slot_data->vbmeta_images[n].vbmeta_data,
                          slot_data->vbmeta_images[n].vbmeta_size);
        total_size += slot_data->vbmeta_images[n].vbmeta_size;
      }
      if (!cmdline_append_option(
              slot_data, "androidboot.vbmeta.hash_alg", "sha512") ||
          !cmdline_append_uint64_base10(
              slot_data, "androidboot.vbmeta.size", total_size) ||
          !cmdline_append_hex(slot_data,
                              "androidboot.vbmeta.digest",
                              avb_sha512_final(&ctx),
                              AVB_SHA512_DIGEST_SIZE)) {
        ret = AVB_SLOT_VERIFY_RESULT_ERROR_OOM;
        goto out;
      }
    } break;
    case _AVB_ALGORITHM_NUM_TYPES:
      avb_assert_not_reached();
      break;
  }

  /* Set androidboot.veritymode and androidboot.vbmeta.invalidate_on_error */
  if (toplevel_vbmeta->flags & AVB_VBMETA_IMAGE_FLAGS_HASHTREE_DISABLED) {
    verity_mode = "disabled";
  } else {
    const char* dm_verity_mode;
    char* new_ret;

    switch (hashtree_error_mode) {
      case AVB_HASHTREE_ERROR_MODE_RESTART_AND_INVALIDATE:
        if (!cmdline_append_option(
                slot_data, "androidboot.vbmeta.invalidate_on_error", "yes")) {
          ret = AVB_SLOT_VERIFY_RESULT_ERROR_OOM;
          goto out;
        }
        verity_mode = "enforcing";
        dm_verity_mode = "restart_on_corruption";
        break;
      case AVB_HASHTREE_ERROR_MODE_RESTART:
        verity_mode = "enforcing";
        dm_verity_mode = "restart_on_corruption";
        break;
      case AVB_HASHTREE_ERROR_MODE_EIO:
        verity_mode = "eio";
        /* For now there's no option to specify the EIO mode. So
         * just use 'ignore_zero_blocks' since that's already set
         * and dm-verity-target.c supports specifying this multiple
         * times.
         */
        dm_verity_mode = "ignore_zero_blocks";
        break;
      case AVB_HASHTREE_ERROR_MODE_LOGGING:
        verity_mode = "logging";
        dm_verity_mode = "ignore_corruption";
        break;
    }
    new_ret = avb_replace(
        slot_data->cmdline, "$(ANDROID_VERITY_MODE)", dm_verity_mode);
    avb_free(slot_data->cmdline);
    slot_data->cmdline = new_ret;
    if (slot_data->cmdline == NULL) {
      ret = AVB_SLOT_VERIFY_RESULT_ERROR_OOM;
      goto out;
    }
  }
  if (!cmdline_append_option(
          slot_data, "androidboot.veritymode", verity_mode)) {
    ret = AVB_SLOT_VERIFY_RESULT_ERROR_OOM;
    goto out;
  }

  ret = AVB_SLOT_VERIFY_RESULT_OK;

out:

  return ret;
}

