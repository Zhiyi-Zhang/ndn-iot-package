/*
 * Copyright (C) 2018-2020
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN-LITE authors and contributors.
 */

#include "ndn-lite-default-ecc-impl.h"
#include "sec-lib/tinycrypt/tc_ecc_dh.h"
#include "sec-lib/tinycrypt/tc_constants.h"
#include "../ndn-lite-ecc.h"
#include "../ndn-lite-sec-utils.h"
#include "../../ndn-constants.h"
#include "../../ndn-error-code.h"
#include "../../ndn-enums.h"
#include <string.h>

#ifndef FEATURE_PERIPH_HWRNG
typedef struct uECC_SHA256_HashContext {
  uECC_HashContext uECC;
  struct tc_sha256_state_struct ctx;
} uECC_SHA256_HashContext;

static void
_init_sha256(uECC_HashContext *base)
{
  uECC_SHA256_HashContext *context = (uECC_SHA256_HashContext*)base;
  tc_sha256_init(&context->ctx);
}

static void
_update_sha256(uECC_HashContext *base,
               const uint8_t *message,
               unsigned message_size)
{
  uECC_SHA256_HashContext *context = (uECC_SHA256_HashContext*)base;
  tc_sha256_update(&context->ctx, message, message_size);
}

static void
_finish_sha256(uECC_HashContext *base, uint8_t *hash_result)
{
  uECC_SHA256_HashContext *context = (uECC_SHA256_HashContext*)base;
  tc_sha256_final(hash_result, &context->ctx);
}
#endif

uint32_t
ndn_lite_default_ecc_get_pub_key_size(const struct abstract_ecc_pub_key* pub_key)
{
  return pub_key->key_size;
}

uint32_t
ndn_lite_default_ecc_get_prv_key_size(const struct abstract_ecc_prv_key* prv_key)
{
  return prv_key->key_size;
}

const uint8_t*
ndn_lite_default_ecc_get_pub_key_value(const struct abstract_ecc_pub_key* pub_key)
{
  return pub_key->key_value;
}

int
ndn_lite_default_ecc_load_pub_key(struct abstract_ecc_pub_key* pub_key,
                                  const uint8_t* key_value, uint32_t key_size)
{
  memset(pub_key->key_value, 0, 64);
  memcpy(pub_key->key_value, key_value, key_size);
  pub_key->key_size = key_size;
  return NDN_SUCCESS;
}

int
ndn_lite_default_ecc_load_prv_key(struct abstract_ecc_prv_key* prv_key,
                                  const uint8_t* key_value, uint32_t key_size)
{
  memset(prv_key->key_value, 0, 32);
  memcpy(prv_key->key_value, key_value, key_size);
  prv_key->key_size = key_size;
  return NDN_SUCCESS;
}

int
ndn_lite_default_ecc_set_rng(ndn_rng_impl rng)
{
  tc_uECC_set_rng(rng);
  uECC_set_rng(rng);
  return NDN_SUCCESS;
}

/**
 * @note Current default backend implementation (i.e., tinycrypt) only supports curve type secp256r1.
 */
int
ndn_lite_default_ecc_dh_shared_secret(const struct abstract_ecc_pub_key* pub_abs_key,
                                      const struct abstract_ecc_prv_key* prv_abs_key,
                                      uint8_t curve_type, uint8_t* output, uint32_t output_size)
{
  if (output_size < 24)
    return NDN_SEC_DISABLED_FEATURE;
  if (curve_type != NDN_ECDSA_CURVE_SECP256R1)
     return NDN_SEC_UNSUPPORT_CRYPTO_ALGO;

  int r = uECC_shared_secret(pub_abs_key->key_value, prv_abs_key->key_value, output);
  if (r == 0)
    return NDN_SEC_CRYPTO_ALGO_FAILURE;
  return NDN_SUCCESS;
}

/**
 * @note Current default backend implementation (i.e., tinycrypt) only supports curve type secp256r1.
 */
int
ndn_lite_default_ecc_make_key(struct abstract_ecc_pub_key* pub_abs_key,
                              struct abstract_ecc_prv_key* prv_abs_key,
                              uint8_t curve_type)
{
  if (curve_type != NDN_ECDSA_CURVE_SECP256R1)
     return NDN_SEC_UNSUPPORT_CRYPTO_ALGO;

  memset(pub_abs_key->key_value, 0, NDN_SEC_ECC_SECP256R1_PUBLIC_KEY_SIZE);
  memset(prv_abs_key->key_value, 0, NDN_SEC_ECC_SECP256R1_PRIVATE_KEY_SIZE);
  int r = uECC_make_key(pub_abs_key->key_value, prv_abs_key->key_value);
  if (r == 0){
    return NDN_SEC_CRYPTO_ALGO_FAILURE;
  }
  pub_abs_key->key_size = NDN_SEC_ECC_SECP256R1_PUBLIC_KEY_SIZE;
  prv_abs_key->key_size = NDN_SEC_ECC_SECP256R1_PRIVATE_KEY_SIZE;
  return NDN_SUCCESS;
}

int
ndn_lite_default_ecdsa_verify(const uint8_t* input_value, uint32_t input_size,
                              const uint8_t* sig_value, uint32_t sig_size,
                              const struct abstract_ecc_pub_key* abs_key, uint8_t ecdsa_type)
{

  if (sig_size > NDN_ASN1_ECDSA_MAX_ENCODED_SIG_SIZE)
    return NDN_SEC_WRONG_SIG_SIZE;
  if (abs_key->key_size > NDN_SEC_ECC_SECP256R1_PUBLIC_KEY_SIZE)
    return NDN_SEC_WRONG_KEY_SIZE;
  if (ecdsa_type != NDN_ECDSA_CURVE_SECP256R1)
    return NDN_SEC_UNSUPPORT_CRYPTO_ALGO;
  if (input_size == 0)
    return NDN_SEC_WRONG_INPUT_SIZE;

  uint8_t raw_sig_temp_buf[NDN_SEC_ECC_SECP256R1_PUBLIC_KEY_SIZE];
  uint32_t decoded_raw_signature_size;
  int ret_val = ndn_asn1_decode_ecdsa_signature(sig_value, sig_size, raw_sig_temp_buf,
                                                NDN_SEC_ECC_SECP256R1_PUBLIC_KEY_SIZE,
                                                &decoded_raw_signature_size);
  if (ret_val != NDN_SUCCESS) {
    return ret_val;
  }

  if (uECC_verify(abs_key->key_value, input_value, raw_sig_temp_buf) == 0) {
    return NDN_SEC_FAIL_VERIFY_SIG;
  }
  else
    return NDN_SUCCESS;
}

int
ndn_lite_default_ecdsa_sign(const uint8_t* input_value, uint32_t input_size,
                            uint8_t* output_value, uint32_t output_max_size,
                            const struct abstract_ecc_prv_key* abs_key,
                            uint8_t ecdsa_type, uint32_t* output_used_size)
{
  if (output_max_size < NDN_SEC_ECC_SECP256R1_PUBLIC_KEY_SIZE)
    return NDN_OVERSIZE;
  if (abs_key->key_size > NDN_SEC_ECC_SECP256R1_PRIVATE_KEY_SIZE)
    return NDN_SEC_WRONG_KEY_SIZE;
  if (ecdsa_type != NDN_ECDSA_CURVE_SECP256R1)
    return NDN_SEC_UNSUPPORT_CRYPTO_ALGO;
  if (input_size == 0)
    return NDN_SEC_WRONG_INPUT_SIZE;

  uint32_t signature_size = NDN_SEC_ECC_SECP256R1_PUBLIC_KEY_SIZE;
  int ecc_sign_result = 0;

#ifndef FEATURE_PERIPH_HWRNG
  uint8_t tmp[NDN_SEC_ECC_SECP256R1_PRIVATE_KEY_SIZE +
              NDN_SEC_ECC_SECP256R1_PRIVATE_KEY_SIZE +
              NDN_SEC_ECC_SECP256R1_PUBLIC_KEY_SIZE];
  uECC_SHA256_HashContext HashContext;
  uECC_SHA256_HashContext* ctx = &HashContext;
  ctx->uECC.init_hash = &_init_sha256;
  ctx->uECC.update_hash = &_update_sha256;
  ctx->uECC.finish_hash = &_finish_sha256;
  ctx->uECC.block_size = NDN_SEC_ECC_SECP256R1_PUBLIC_KEY_SIZE;
  ctx->uECC.result_size = NDN_SEC_ECC_SECP256R1_PRIVATE_KEY_SIZE;
  ctx->uECC.tmp = tmp;

  ecc_sign_result = uECC_sign_deterministic(abs_key->key_value, input_value,
                                            &ctx->uECC, output_value);
#else
  ecc_sign_result = uECC_sign(abs_key->key_value, input_value, output_value);
#endif
  if (ecc_sign_result == 0) {
    return NDN_SEC_CRYPTO_ALGO_FAILURE;
  }

  uint32_t encoded_sig_length;
  int ret_val = ndn_asn1_probe_ecdsa_signature_encoding_size(output_value, signature_size,
                                                             &encoded_sig_length);
  if (ret_val != NDN_SUCCESS) {
    return ret_val;
  }

  ret_val = ndn_asn1_encode_ecdsa_signature(output_value, signature_size, output_max_size);
  if (ret_val != NDN_SUCCESS) {
    return ret_val;
  }

  *output_used_size = encoded_sig_length;

  return NDN_SUCCESS;
}

void
ndn_lite_default_ecc_load_backend(void)
{
  ndn_ecc_backend_t* ecc_back = ndn_ecc_get_backend();
  ecc_back->get_pub_key_size = ndn_lite_default_ecc_get_pub_key_size;
  ecc_back->get_prv_key_size = ndn_lite_default_ecc_get_prv_key_size;
  ecc_back->get_pub_key_value = ndn_lite_default_ecc_get_pub_key_value;
  ecc_back->load_pub_key = ndn_lite_default_ecc_load_pub_key;
  ecc_back->load_prv_key = ndn_lite_default_ecc_load_prv_key;
  ecc_back->set_rng = ndn_lite_default_ecc_set_rng;
  ecc_back->make_key = ndn_lite_default_ecc_make_key;
  ecc_back->dh_shared_secret = ndn_lite_default_ecc_dh_shared_secret;
  ecc_back->ecdsa_sign = ndn_lite_default_ecdsa_sign;
  ecc_back->ecdsa_verify = ndn_lite_default_ecdsa_verify;
}
