#include <android-base/file.h>
#include <base/files/file_util.h>
#include <libavb/libavb.h>
#include "assert.h"

#include <fstream>
#include <iostream>
#include <string>

typedef struct _FuzzInput {
  const uint8_t* buf;
  size_t len;
} FuzzInput;

const char empty_img_folder[] = "test/data/empty_images";
extern "C" int LLVMFuzzerTestOneInput(uint8_t* buf, size_t len);
AvbIOResult get_size_of_partition(AvbOps* ops,
                                  const char* partition,
                                  uint64_t* out_size_num_bytes);
AvbIOResult read_from_partition(AvbOps* ops,
                                const char* partition,
                                int64_t offset,
                                size_t num_bytes,
                                void* buffer,
                                size_t* out_num_read);
AvbIOResult read_is_device_unlocked(AvbOps* _ops, bool* out_is_unlocked);
AvbIOResult validate_vbmeta_public_key(AvbOps* _ops,
                                       const uint8_t* _public_key_data,
                                       size_t _public_key_length,
                                       const uint8_t* _public_key_metadata,
                                       size_t _public_key_metadata_length,
                                       bool* out_is_trusted);
AvbIOResult read_rollback_index(AvbOps* _ops,
                                size_t _rollback_index_location,
                                uint64_t* out_rollback_index);
AvbIOResult get_unique_guid_for_partition(AvbOps* _ops,
                                          const char* _partition,
                                          char* guid_buf,
                                          size_t guid_buf_size);

AvbIOResult get_size_of_partition(AvbOps* ops,
                                  const char* partition,
                                  uint64_t* out_size_num_bytes) {
  /* Change current directory to test executable directory so that relative path
   * references to test dependencies don't rely on being manually run from
   * correct directory */
  base::SetCurrentDirectory(
      base::FilePath(android::base::GetExecutableDirectory()));
  if (strlen(partition) >= 2 &&
      strcmp(partition + strlen(partition) - 2, "_a") == 0) {
    if (!strcmp(partition, "vbmeta_a")) {
      // For vbmeta partition, we return the fuzzing input.
      FuzzInput* fuzz_input = reinterpret_cast<FuzzInput*>(ops->user_data);
      *out_size_num_bytes = reinterpret_cast<uint64_t>(fuzz_input->len);
      return AVB_IO_RESULT_OK;
    } else {
      std::string partition_s = std::string(partition);
      partition_s = partition_s.substr(0, partition_s.length() - 2);
      base::FilePath folder_path = base::FilePath(empty_img_folder);
      base::FilePath file_path =
          folder_path.Append(std::string(partition_s) + ".img");
      if (base::PathExists(file_path)) {
        int64_t file_size = 0;
        if (!GetFileSize(file_path, &file_size)) {
          // Should never happen.
          __builtin_trap();
        }
        *out_size_num_bytes = static_cast<uint64_t>(file_size);
      } else {
        // We do not have this partition, just return error.
        return AVB_IO_RESULT_ERROR_IO;
      }
    }
  }
  return AVB_IO_RESULT_ERROR_IO;
}

AvbIOResult read_from_partition(AvbOps* ops,
                                const char* partition,
                                int64_t offset,
                                size_t num_bytes,
                                void* buffer,
                                size_t* out_num_read) {
  /* Change current directory to test executable directory so that relative path
   * references to test dependencies don't rely on being manually run from
   * correct directory */
  base::SetCurrentDirectory(
      base::FilePath(android::base::GetExecutableDirectory()));
  if (offset < 0) {
    size_t partition_size;
    AvbIOResult result = get_size_of_partition(ops, partition, &partition_size);
    if (result != AVB_IO_RESULT_OK) {
      return result;
    }
    offset = partition_size + offset;
  }

  if (strlen(partition) >= 2 &&
      strcmp(partition + strlen(partition) - 2, "_a") == 0) {
    if (!strcmp(partition, "vbmeta_a")) {
      // For vbmeta partition, we return the fuzzing input.
      FuzzInput* fuzz_input = reinterpret_cast<FuzzInput*>(ops->user_data);
      size_t bytes_to_read = num_bytes;
      if (offset + num_bytes > fuzz_input->len) {
        bytes_to_read = fuzz_input->len - offset;
      }
      memcpy(buffer, fuzz_input->buf + offset, bytes_to_read);
      *out_num_read = bytes_to_read;
      return AVB_IO_RESULT_OK;
    } else {
      std::string partition_s = std::string(partition);
      partition_s = partition_s.substr(0, partition_s.length() - 2);
      base::FilePath folder_path = base::FilePath(empty_img_folder);
      base::FilePath file_path =
          folder_path.Append(std::string(partition_s) + ".img");
      if (base::PathExists(file_path)) {
        std::string content;
        if (!base::ReadFileToStringWithMaxSize(
                file_path, &content, num_bytes)) {
          // Should never happen.
          __builtin_trap();
        }
        memcpy(buffer, content.c_str(), content.length());
        *out_num_read = content.length();
      } else {
        // We do not have this partition, just return error.
        return AVB_IO_RESULT_ERROR_IO;
      }
    }
  }
  return AVB_IO_RESULT_ERROR_IO;
}

AvbIOResult read_is_device_unlocked(AvbOps* _ops, bool* out_is_unlocked) {
  // Prevent unused warning.
  (void)_ops;
  *out_is_unlocked = false;
  return AVB_IO_RESULT_OK;
}

AvbIOResult validate_vbmeta_public_key(AvbOps* _ops,
                                       const uint8_t* _public_key_data,
                                       size_t _public_key_length,
                                       const uint8_t* _public_key_metadata,
                                       size_t _public_key_metadata_length,
                                       bool* out_is_trusted) {
  // Prevent unused warning.
  (void)_ops;
  (void)_public_key_data;
  (void)_public_key_length;
  (void)_public_key_metadata;
  (void)_public_key_metadata_length;
  *out_is_trusted = true;
  return AVB_IO_RESULT_OK;
}

AvbIOResult read_rollback_index(AvbOps* _ops,
                                size_t _rollback_index_location,
                                uint64_t* out_rollback_index) {
  // Prevent unused warning.
  (void)_ops;
  (void)_rollback_index_location;
  *out_rollback_index = 0;
  return AVB_IO_RESULT_OK;
}

AvbIOResult get_unique_guid_for_partition(AvbOps* _ops,
                                          const char* _partition,
                                          char* guid_buf,
                                          size_t guid_buf_size) {
  // Prevent unused warning.
  (void)_ops;
  (void)_partition;
  memset(guid_buf, 0, guid_buf_size);
  return AVB_IO_RESULT_OK;
}

extern "C" int LLVMFuzzerTestOneInput(uint8_t* buf, size_t len) {
  AvbSlotVerifyData* slot_data = NULL;
  const char* requested_partitions[] = {"boot", NULL};
  AvbOps ops;
  memset(&ops, 0, sizeof(AvbOps));
  ops.read_from_partition = &read_from_partition;
  ops.read_is_device_unlocked = &read_is_device_unlocked;
  ops.validate_vbmeta_public_key = &validate_vbmeta_public_key;
  ops.read_rollback_index = &read_rollback_index;
  ops.get_unique_guid_for_partition = &get_unique_guid_for_partition;
  ops.get_size_of_partition = &get_size_of_partition;
  FuzzInput fuzz_input;
  fuzz_input.buf = buf;
  fuzz_input.len = len;
  ops.user_data = &fuzz_input;
  (void)avb_slot_verify(&ops,
                        requested_partitions,
                        "_a",
                        AVB_SLOT_VERIFY_FLAGS_ALLOW_VERIFICATION_ERROR,
                        AVB_HASHTREE_ERROR_MODE_RESTART_AND_INVALIDATE,
                        &slot_data);
  if (slot_data != NULL) {
    avb_slot_verify_data_free(slot_data);
  }
  return 0;
}
