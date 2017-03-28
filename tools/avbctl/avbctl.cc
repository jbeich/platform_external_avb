/*
 * Copyright (C) 2017 The Android Open Source Project
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

#include <sysexits.h>

#include <stdio.h>
#include <string.h>

#include <android/hardware/boot/1.0/IBootControl.h>

#include <libavb_user/libavb_user.h>

using android::sp;
using android::hardware::hidl_string;
using android::hardware::Return;
using android::hardware::boot::V1_0::IBootControl;
using android::hardware::boot::V1_0::Slot;

static void usage(FILE* where, int /* argc */, char* argv[]) {
  fprintf(where,
          "%s - command-line tool for AVB.\n"
          "\n"
          "Usage:\n"
          "  %s COMMAND\n"
          "\n"
          "Commands:\n"
          "  %s disable-verity    - Disable verity in current slot.\n"
          "  %s enable-verity     - Enable verity in current slot.\n",
          argv[0],
          argv[0],
          argv[0],
          argv[0]);
}

static std::string get_suffix(sp<IBootControl> module) {
  std::string suffix = "";

  if (module != nullptr) {
    uint32_t num_slots = module->getNumberSlots();
    if (num_slots > 1) {
      Slot cur_slot = module->getCurrentSlot();
      Return<void> ret =
          module->getSuffix(cur_slot, [&suffix](const hidl_string& value) {
            suffix = std::string(value.c_str());
          });
      if (!ret.isOk()) {
        fprintf(stderr, "Error getting suffix for slot %d.\n", cur_slot);
      }
    }
  }

  return suffix;
}

static int do_set_verity(AvbOps* ops,
                         sp<IBootControl> module,
                         bool enable_verity) {
  std::string partition;
  uint8_t vbmeta_image[AVB_VBMETA_IMAGE_HEADER_SIZE];  // 256 bytes.
  size_t num_read;
  AvbIOResult io_res;

  partition = std::string("vbmeta") + get_suffix(module);

  // Only read the header.
  io_res = ops->read_from_partition(ops,
                                    partition.c_str(),
                                    0,
                                    AVB_VBMETA_IMAGE_HEADER_SIZE,
                                    vbmeta_image,
                                    &num_read);
  if (io_res != AVB_IO_RESULT_OK) {
    fprintf(stderr,
            "Error loading from partition '%s' (%d).\n",
            partition.c_str(),
            io_res);
    return EX_SOFTWARE;
  }

  // Sanity check the magic.
  if (memcmp(vbmeta_image, "AVB0", 4) != 0) {
    fprintf(stderr,
            "Data from '%s' does not look like a vbmeta partition.\n",
            partition.c_str());
    return EX_SOFTWARE;
  }

  // Set/clear the HASHTREE_DISABLED bit, as requested.
  AvbVBMetaImageHeader* header =
      reinterpret_cast<AvbVBMetaImageHeader*>(vbmeta_image);
  uint32_t flags = avb_be32toh(header->flags);
  flags &= ~AVB_VBMETA_IMAGE_FLAGS_HASHTREE_DISABLED;
  if (!enable_verity) {
    flags |= AVB_VBMETA_IMAGE_FLAGS_HASHTREE_DISABLED;
  }
  header->flags = avb_htobe32(flags);

  // Write the header.
  io_res = ops->write_to_partition(
      ops, partition.c_str(), 0, AVB_VBMETA_IMAGE_HEADER_SIZE, vbmeta_image);
  if (io_res != AVB_IO_RESULT_OK) {
    fprintf(stderr,
            "Error writing to partition '%s' (%d).\n",
            partition.c_str(),
            io_res);
    return EX_SOFTWARE;
  }

  fprintf(stdout,
          "Successfully %s verity on %s.\n",
          enable_verity ? "enabled" : "disabled",
          partition.c_str());

  return EX_OK;
}

int main(int argc, char* argv[]) {
  int ret;
  sp<IBootControl> module;
  AvbOps* ops = nullptr;

  if (argc < 2) {
    usage(stderr, argc, argv);
    ret = EX_USAGE;
    goto out;
  }

  ops = avb_ops_user_new();
  if (ops == nullptr) {
    fprintf(stderr, "Error getting AVB ops.\n");
    ret = EX_SOFTWARE;
    goto out;
  }

  // Failing to get the boot_control HAL is not a fatal error - it can
  // happen if A/B is not in use, in which case |nullptr| is returned.
  module = IBootControl::getService();

  if (strcmp(argv[1], "disable-verity") == 0) {
    ret = do_set_verity(ops, module, false);
  } else if (strcmp(argv[1], "enable-verity") == 0) {
    ret = do_set_verity(ops, module, true);
  } else {
    usage(stderr, argc, argv);
    ret = EX_USAGE;
  }

  ret = EX_OK;
out:
  if (ops != nullptr) {
    avb_ops_user_free(ops);
  }
  return ret;
}
