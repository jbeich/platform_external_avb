// TODO what copyright header should I use?

#ifndef AVB_CURVE25519_H
#define AVB_CURVE25519_H

/**
 * This file is created from curve25519 related code in the boringssl.
 * Only EdDSA related functions and only
 * OPENSSL_SMALL, OPENSSL_32_BIT, OPENSSL_NO_ASM and
 * FIAT_25519_NO_ASM code is copied.
 */
#ifdef __cplusplus
extern "C" {
#endif
#include <string.h>

#include "../../avb_sysdeps.h"
#include "../../avb_util.h"

// Curve25519.
//
// Curve25519 is an elliptic curve. See https://tools.ietf.org/html/rfc7748.

// Ed25519.
//
// Ed25519 is a signature scheme using a twisted-Edwards curve that is
// birationally equivalent to curve25519.
//
// Note that, unlike RFC 8032's formulation, our private key representation
// includes a public key suffix to make multiple key signing operations with the
// same key more efficient. The RFC 8032 private key is referred to in this
// implementation as the "seed" and is the first 32 bytes of our private key.

#define ED25519_PRIVATE_KEY_LEN 64
#define ED25519_PUBLIC_KEY_LEN 32
#define ED25519_SIGNATURE_LEN 64

// fe means field element. Here the field is \Z/(2^255-19). An element t,
// entries t[0]...t[9], represents the integer t[0]+2^26 t[1]+2^51 t[2]+2^77
// t[3]+2^102 t[4]+...+2^230 t[9].
// fe limbs are bounded by 1.125*2^26,1.125*2^25,1.125*2^26,1.125*2^25,etc.
// Multiplication and carrying produce fe from fe_loose.
typedef struct fe {
  uint32_t v[10];
} fe;

// fe_loose limbs are bounded
// by 3.375*2^26,3.375*2^25,3.375*2^26,3.375*2^25,etc. Addition and subtraction
// produce fe_loose from (fe, fe).
typedef struct fe_loose {
  uint32_t v[10];
} fe_loose;

// ge means group element.
//
// Here the group is the set of pairs (x,y) of field elements (see fe.h)
// satisfying -x^2 + y^2 = 1 + d x^2y^2
// where d = -121665/121666.
//
// Representations:
//   ge_p2 (projective): (X:Y:Z) satisfying x=X/Z, y=Y/Z
//   ge_p3 (extended): (X:Y:Z:T) satisfying x=X/Z, y=Y/Z, XY=ZT
//   ge_p1p1 (completed): ((X:Z),(Y:T)) satisfying x=X/Z, y=Y/T
//   ge_precomp (Duif): (y+x,y-x,2dxy)

typedef struct {
  fe X;
  fe Y;
  fe Z;
} ge_p2;

typedef struct {
  fe X;
  fe Y;
  fe Z;
  fe T;
} ge_p3;

typedef struct {
  fe_loose X;
  fe_loose Y;
  fe_loose Z;
  fe_loose T;
} ge_p1p1;

typedef struct {
  fe_loose yplusx;
  fe_loose yminusx;
  fe_loose xy2d;
} ge_precomp;

typedef struct {
  fe_loose YplusX;
  fe_loose YminusX;
  fe_loose Z;
  fe_loose T2d;
} ge_cached;

void x25519_ge_tobytes(uint8_t s[32], const ge_p2* h);
int x25519_ge_frombytes_vartime(ge_p3* h, const uint8_t s[32]);
void x25519_ge_p3_to_cached(ge_cached* r, const ge_p3* p);
void x25519_ge_p1p1_to_p2(ge_p2* r, const ge_p1p1* p);
void x25519_ge_p1p1_to_p3(ge_p3* r, const ge_p1p1* p);
void x25519_ge_add(ge_p1p1* r, const ge_p3* p, const ge_cached* q);
void x25519_ge_sub(ge_p1p1* r, const ge_p3* p, const ge_cached* q);
void x25519_ge_scalarmult_small_precomp(
    ge_p3* h, const uint8_t a[32], const uint8_t precomp_table[15 * 2 * 32]);
void x25519_ge_scalarmult_base(ge_p3* h, const uint8_t a[32]);
void x25519_ge_scalarmult(ge_p2* r, const uint8_t* scalar, const ge_p3* A);
void x25519_sc_reduce(uint8_t s[64]);

// crypto_word_t is the type that most constant-time functions use. Ideally we
// would like it to be |size_t|, but NaCl builds in 64-bit mode with 32-bit
// pointers, which means that |size_t| can be 32 bits when |BN_ULONG| is 64
// bits. Since we want to be able to do constant-time operations on a
// |BN_ULONG|, |crypto_word_t| is defined as an unsigned value with the native
// word length.
typedef uint32_t crypto_word_t;

// |value_barrier_u8| could be defined as above, but compilers other than
// clang seem to still materialize 0x00..00MM instead of reusing 0x??..??MM.

// constant_time_msb_w returns the given value with the MSB copied to all the
// other bits.
static inline crypto_word_t constant_time_msb_w(crypto_word_t a) {
  return 0u - (a >> (sizeof(a) * 8 - 1));
}

// constant_time_lt_w returns 0xff..f if a < b and 0 otherwise.
static inline crypto_word_t constant_time_lt_w(crypto_word_t a,
                                               crypto_word_t b) {
  // Consider the two cases of the problem:
  //   msb(a) == msb(b): a < b iff the MSB of a - b is set.
  //   msb(a) != msb(b): a < b iff the MSB of b is set.
  //
  // If msb(a) == msb(b) then the following evaluates as:
  //   msb(a^((a^b)|((a-b)^a))) ==
  //   msb(a^((a-b) ^ a))       ==   (because msb(a^b) == 0)
  //   msb(a^a^(a-b))           ==   (rearranging)
  //   msb(a-b)                      (because ∀x. x^x == 0)
  //
  // Else, if msb(a) != msb(b) then the following evaluates as:
  //   msb(a^((a^b)|((a-b)^a))) ==
  //   msb(a^(𝟙 | ((a-b)^a)))   ==   (because msb(a^b) == 1 and 𝟙
  //                                  represents a value s.t. msb(𝟙) = 1)
  //   msb(a^𝟙)                 ==   (because ORing with 1 results in 1)
  //   msb(b)
  //
  //
  // Here is an SMT-LIB verification of this formula:
  //
  // (define-fun lt ((a (_ BitVec 32)) (b (_ BitVec 32))) (_ BitVec 32)
  //   (bvxor a (bvor (bvxor a b) (bvxor (bvsub a b) a)))
  // )
  //
  // (declare-fun a () (_ BitVec 32))
  // (declare-fun b () (_ BitVec 32))
  //
  // (assert (not (= (= #x00000001 (bvlshr (lt a b) #x0000001f)) (bvult a b))))
  // (check-sat)
  // (get-model)
  return constant_time_msb_w(a ^ ((a ^ b) | ((a - b) ^ a)));
}

// constant_time_lt_8 acts like |constant_time_lt_w| but returns an 8-bit
// mask.
static inline uint8_t constant_time_lt_8(crypto_word_t a, crypto_word_t b) {
  return (uint8_t)(constant_time_lt_w(a, b));
}

// constant_time_ge_w returns 0xff..f if a >= b and 0 otherwise.
static inline crypto_word_t constant_time_ge_w(crypto_word_t a,
                                               crypto_word_t b) {
  return ~constant_time_lt_w(a, b);
}

// constant_time_ge_8 acts like |constant_time_ge_w| but returns an 8-bit
// mask.
static inline uint8_t constant_time_ge_8(crypto_word_t a, crypto_word_t b) {
  return (uint8_t)(constant_time_ge_w(a, b));
}

// constant_time_is_zero returns 0xff..f if a == 0 and 0 otherwise.
static inline crypto_word_t constant_time_is_zero_w(crypto_word_t a) {
  // Here is an SMT-LIB verification of this formula:
  //
  // (define-fun is_zero ((a (_ BitVec 32))) (_ BitVec 32)
  //   (bvand (bvnot a) (bvsub a #x00000001))
  // )
  //
  // (declare-fun a () (_ BitVec 32))
  //
  // (assert (not (= (= #x00000001 (bvlshr (is_zero a) #x0000001f)) (= a
  // #x00000000)))) (check-sat) (get-model)
  return constant_time_msb_w(~a & (a - 1));
}

// constant_time_is_zero_8 acts like |constant_time_is_zero_w| but returns an
// 8-bit mask.
static inline uint8_t constant_time_is_zero_8(crypto_word_t a) {
  return (uint8_t)(constant_time_is_zero_w(a));
}

// constant_time_eq_w returns 0xff..f if a == b and 0 otherwise.
static inline crypto_word_t constant_time_eq_w(crypto_word_t a,
                                               crypto_word_t b) {
  return constant_time_is_zero_w(a ^ b);
}

// constant_time_eq_8 acts like |constant_time_eq_w| but returns an 8-bit
// mask.
static inline uint8_t constant_time_eq_8(crypto_word_t a, crypto_word_t b) {
  return (uint8_t)(constant_time_eq_w(a, b));
}

// constant_time_eq_int acts like |constant_time_eq_w| but works on int
// values.
static inline crypto_word_t constant_time_eq_int(int a, int b) {
  return constant_time_eq_w((crypto_word_t)(a), (crypto_word_t)(b));
}

static inline uint64_t CRYPTO_load_u64_le(const void* in) {
  uint64_t v;
  memcpy(&v, in, sizeof(v));
  return v;
}

#ifdef __cplusplus
}
#endif

#endif
