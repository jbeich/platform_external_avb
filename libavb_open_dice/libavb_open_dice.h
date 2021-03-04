/*
 * Copyright (C) 2021 The Android Open Source Project
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

#ifndef AVB_OPEN_DICE_H_
#define AVB_OPEN_DICE_H_

#include <libavb/libavb.h>

#ifdef __cplusplus
extern "C" {
#endif

#define AVB_OPEN_DICE_CDI_SIZE 32
#define AVB_OPEN_DICE_HIDDEN_SIZE 64

#define AVB_OPEN_DICE_CONFIG_COMPONENT_NAME_LABEL -70002
#define AVB_OPEN_DICE_CONFIG_VERSION_LABEL -70003
#define AVB_OPEN_DICE_CONFIG_RESETTABLE_LABEL -70004
#define AVB_OPEN_DICE_CONFIG_ACTIVE_AUTHORITY_LABEL -70004

/* Return codes used in avb_open_dice_generate(). */
typedef enum {
  AVB_OPEN_DICE_RESULT_OK,
  AVB_OPEN_DICE_RESULT_ERROR_OOM,
  AVB_OPEN_DICE_RESULT_ERROR_CERTIFICATE,
} AvbOpenDiceResult;

/* Selects the mode used in the open-dice derivation. */
typedef enum {
  AVB_OPEN_DICE_MODE_DEBUG,
  AVB_OPEN_DICE_MODE_NORMAL,
} AvbOpenDiceMode;

/* AvbOpenDiceData contains the result of an open-dice derivation. |cert| points
 * to the certificate that is |cert_size| bytes in size and can be verified with
 * |verifying_public_key|. |cdi_attest| and |cdi_seal| hold the attestation and
 * sealing CDIs produced in the derivation.
 */
typedef struct {
  uint8_t* cert;
  size_t cert_size;
  uint8_t cdi_attest[AVB_OPEN_DICE_CDI_SIZE];
  uint8_t cdi_seal[AVB_OPEN_DICE_CDI_SIZE];
} AvbOpenDiceData;

struct AvbOpenDiceOps;
typedef struct AvbOpenDiceOps AvbOpenDiceOps;

/* An extension to AvbOps required by avb_open_dice_generate(). */
struct AvbOpenDiceOps {
  /* Operations from libavb. */
  AvbOps* ops;

  /* Securely clears |size| bytes at |address|. This is used to destroy
   * sensitive data so the implementation must ensure the data is not
   * recoverable after this function is called, which may require consideration
   * of system components such as caches.
   */
  void (*clear_memory)(AvbOpenDiceOps* ops, size_t size, void* address);
};

/* Frees a |AvbOpenDiceData| including all data it points to, clearing the
 * sensitive fields in the process.
 */
void avb_open_dice_data_free(AvbOpenDiceOps* ops, AvbOpenDiceData* data);

/* Populates a |AvbOpenDiceData| with the results from an open-dice derivation
 * for the verification described in |slot_data|.
 *
 * |cdi_attest| and |cdi_seal| are the CDIs of the calling code from which the
 * new CDIs will be derived based on the other inputs.
 *
 * The |hidden| input is used to link the generation to the device lifecycle. A
 * value that only changes at factory reset is an example of this.
 *
 * The |mode| differentiates between a secure boot or a boot that could be
 * tampered with. For example, use |AVB_OPEN_DICE_MODE_NORMAL| when the device
 * is locked and |AVB_OPEN_DICE_MODE_DEBUG| when the device is unlocked.
 *
 * If the inputs are such that they will change on factory reset, |resettable|
 * should be |true|, otherwise it must be |false|.
 *
 * The |authority_hash| is a hash of the trusted verifying authority. See the
 * Open Profile for DICE for a full specification of this value, but most
 * importantly, it must be stable across boots so must capture all permissible
 * public keys. For example, when using ATX, a |hash| of the permanent
 * attributes would be suitable.
 *
 * If the function returns successfully, |out_data| will have been allocated
 * and populated and |avb_open_dice_data_free| should be called to wipe
 * sensitive data and free memory.
 */
AvbOpenDiceResult avb_open_dice_generate(
    AvbOpenDiceOps* ops,
    const uint8_t cdi_attest[AVB_OPEN_DICE_CDI_SIZE],
    const uint8_t cdi_seal[AVB_OPEN_DICE_CDI_SIZE],
    AvbOpenDiceMode mode,
    bool resettable,
    const uint8_t hidden[AVB_OPEN_DICE_HIDDEN_SIZE],
    const uint8_t authority_hash[AVB_SHA512_DIGEST_SIZE],
    const AvbSlotVerifyData* slot_data,
    AvbOpenDiceData** out_data);

#ifdef __cplusplus
}
#endif

#endif /* AVB_OPEN_DICE_H_ */
