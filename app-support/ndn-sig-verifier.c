/*
 * Copyright (C) 2018-2020
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN-LITE authors and contributors.
 */
#define ENABLE_NDN_LOG_DEBUG 1
#define ENABLE_NDN_LOG_ERROR 1
#include "ndn-sig-verifier.h"
#include "../encode/signed-interest.h"
#include "../encode/key-storage.h"
#include "../util/uniform-time.h"
#include "../util/logger.h"

typedef struct ndn_sig_verifier_state {
  ndn_face_intf_t* face;
} ndn_sig_verifier_state_t;

typedef struct ndn_sig_verifier_userdata {
  bool is_interest;
  void* original_pkt;
  void* on_success_cbk;
  void* on_success_userdata;
  void* on_failure_cbk;
  void* on_failure_userdata;
} ndn_sig_verifier_userdata_t;

static ndn_sig_verifier_userdata_t m_userdata;
static ndn_sig_verifier_state_t m_sig_verifier_state;
static uint8_t verifier_buf[4096];

#if ENABLE_NDN_LOG_DEBUG
static ndn_time_us_t m_measure_tp1 = 0;
static ndn_time_us_t m_measure_tp2 = 0;
#endif

void
sig_verifier_on_data(const uint8_t* raw_data, uint32_t data_size, void* userdata)
{
  ndn_sig_verifier_userdata_t* dataptr = (ndn_sig_verifier_userdata_t*)userdata;

  ndn_data_t cert;
  uint32_t start, end;
  ndn_data_tlv_decode_no_verify(&cert, raw_data, data_size, &start, &end);
  NDN_LOG_DEBUG("[SIGVERIFIER] SigVerifier received certificate: ");
  NDN_LOG_DEBUG_NAME(&cert.name);
  // use trust anchor key to verify
  ndn_key_storage_t* keys = ndn_key_storage_get_instance();
  int result = ndn_ecdsa_verify(raw_data + start, end - start,
                                cert.signature.sig_value, cert.signature.sig_size, &keys->trust_anchor_key);
  if (result == NDN_SUCCESS) {
    // add the received certificate to key storage
    ndn_key_storage_add_trusted_certificate(&cert);
    ndn_ecc_pub_t* pub_key = NULL;
    // verify the original interest/data
    if (dataptr->is_interest) {
      ndn_interest_t* original_int = (ndn_interest_t*)dataptr->original_pkt;
      uint32_t keyid = key_id_from_key_name(&original_int->signature.key_locator_name);
      pub_key = ndn_key_storage_get_ecc_pub_key(keyid);
      if (!pub_key) {
        NDN_LOG_ERROR("[SIGVERIFIER] Still cannot get public key from local key storage\n");
      }
      result = ndn_signed_interest_ecdsa_verify(original_int, pub_key);
      if (result == NDN_SUCCESS) {
        on_int_verification_success on_success = (on_int_verification_success)(dataptr->on_success_cbk);
        on_success(original_int, dataptr->on_success_userdata);
        return;
      }
    }
    else {
      ndn_data_t* original_dat = (ndn_data_t*)dataptr->original_pkt;
      uint32_t keyid = key_id_from_key_name(&original_dat->signature.key_locator_name);
      pub_key = ndn_key_storage_get_ecc_pub_key(keyid);

      ndn_encoder_t encoder;
      encoder_init(&encoder, verifier_buf, sizeof(verifier_buf));
      ndn_data_tlv_encode(&encoder, original_dat);
      if (!pub_key) {
          NDN_LOG_ERROR("[SIGVERIFIER] Still cannot get public key from local key storage\n");
      }
      result = ndn_data_tlv_decode_ecdsa_verify(original_dat, verifier_buf, encoder.offset, pub_key);
      if (result == NDN_SUCCESS) {
        on_data_verification_success on_success = (on_data_verification_success)(dataptr->on_success_cbk);
        on_success(original_dat, dataptr->on_success_userdata);
        return;
      }
    }
  }
  // otherwise, invoke on_failure callbacks
  if (dataptr->is_interest) {
    on_int_verification_failure on_failure = (on_int_verification_failure)(dataptr->on_failure_cbk);
    on_failure((ndn_interest_t*)dataptr->original_pkt, dataptr->on_failure_userdata);
  }
  else {
    on_data_verification_failure on_failure = (on_data_verification_failure)(dataptr->on_failure_cbk);
    on_failure((ndn_data_t*)dataptr->original_pkt, dataptr->on_failure_userdata);
  }
}

void
sig_verifier_on_timeout(void* userdata)
{
  NDN_LOG_DEBUG("[SIGVERIFIER] SigVerifier cert fetch interest timeout\n");
  ndn_sig_verifier_userdata_t* dataptr = (ndn_sig_verifier_userdata_t*)userdata;
  if (dataptr->is_interest) {
    on_int_verification_failure on_failure = (on_int_verification_failure)(dataptr->on_failure_cbk);
    on_failure((ndn_interest_t*)dataptr->original_pkt, dataptr->on_failure_userdata);
  }
  else {
    on_data_verification_failure on_failure = (on_data_verification_failure)(dataptr->on_failure_cbk);
    on_failure((ndn_data_t*)dataptr->original_pkt, dataptr->on_failure_userdata);
  }
}

int
sig_verifier_on_interest(const uint8_t* raw_int, uint32_t raw_int_size, void* userdata)
{
  (void) userdata;
  ndn_interest_t interest;
  ndn_interest_from_block(&interest, raw_int, raw_int_size);
  NDN_LOG_DEBUG("[SIGVERIFIER] SigVerifier received certificate fetching Interest: ");
  ndn_name_print(&interest.name);
  ndn_key_storage_t* storage = ndn_key_storage_get_instance();
  for (int i = 0; i < NDN_SEC_CERT_SIZE; i++) {
    if (ndn_name_is_prefix_of(&interest.name, &storage->self_cert[i].name) == NDN_SUCCESS) {
      ndn_encoder_t encoder;
      encoder_init(&encoder, verifier_buf, sizeof(verifier_buf));
      ndn_data_tlv_encode(&encoder, &storage->self_cert[i]);
      NDN_LOG_DEBUG("[SIGVERIFIER] Giving back self certificate: \n");
      NDN_LOG_DEBUG_NAME(&storage->self_cert[i].name);
      int ret = ndn_forwarder_put_data(encoder.output_value, encoder.offset);
      if (ret) {
        NDN_LOG_ERROR("[SIGVERIFIER] Cannot put back data, error code is %d", ret);
      }
      break;
    }
  }
  return NDN_FWD_STRATEGY_SUPPRESS;
}

void
ndn_sig_verifier_after_bootstrapping(ndn_face_intf_t* face)
{
  m_sig_verifier_state.face = face;
  ndn_name_t prefix;
  ndn_key_storage_t* storage = ndn_key_storage_get_instance();
  for (int i = 0; i < NDN_SEC_CERT_SIZE; i++) {
    if (storage->self_identity_key[i].key_id != NDN_SEC_INVALID_KEY_ID) {
      memcpy(&prefix, &storage->self_identity[i], sizeof(ndn_name_t));
      NDN_LOG_DEBUG("[SIGVERIFIER] SigVerifier register prefix for: ");
      NDN_LOG_DEBUG_NAME(&prefix);
      ndn_forwarder_register_name_prefix(&prefix, sig_verifier_on_interest, NULL);
    }
  }
}

void
ndn_sig_verifier_verify_int(const uint8_t* raw_pkt, size_t pkt_size,
                            on_int_verification_success on_success, void* on_success_userdata,
                            on_int_verification_failure on_failure, void* on_failure_userdata)
{
  static ndn_interest_t interest;

#if ENABLE_NDN_LOG_DEBUG
  m_measure_tp1 = ndn_time_now_us();
#endif

  ndn_interest_from_block(&interest, raw_pkt, pkt_size);

#if ENABLE_NDN_LOG_DEBUG
  m_measure_tp2 = ndn_time_now_us();
  NDN_LOG_DEBUG("[SIGVERIFIER] DATA-PKT-DECODING: %" PRI_ndn_time_us_t "\n", m_measure_tp2 - m_measure_tp1);
#endif

  if (!ndn_interest_is_signed(&interest)) {
    on_success(&interest, on_success_userdata);
    return;
  }
  if (interest.signature.sig_type < 0 || interest.signature.sig_type > 4) {
    on_failure(&interest, on_success_userdata);
    return;
  }
  int result = 0;
  if (interest.signature.sig_type == NDN_SIG_TYPE_DIGEST_SHA256) {
    result = ndn_signed_interest_digest_verify(&interest);
    if (result == NDN_SUCCESS) on_success(&interest, on_success_userdata);
    else on_failure(&interest, on_failure_userdata);
  }
  if (interest.signature.enable_KeyLocator <= 0) {
    on_failure(&interest, on_failure_userdata);
    return;
  }
  uint32_t keyid = key_id_from_key_name(&interest.signature.key_locator_name);
  bool need_interest_out = false;
  if (interest.signature.sig_type == NDN_SIG_TYPE_ECDSA_SHA256) {
    ndn_ecc_pub_t* pub_key = ndn_key_storage_get_ecc_pub_key(keyid);
    if (pub_key == NULL) {
      need_interest_out = true;
    }
    else {
      result = ndn_signed_interest_ecdsa_verify(&interest, pub_key);
      if (result == NDN_SUCCESS) on_success(&interest, on_success_userdata);
      else on_failure(&interest, on_failure_userdata);
      return;
    }
  }
  else if (interest.signature.sig_type == NDN_SIG_TYPE_HMAC_SHA256) {
    ndn_hmac_key_t* hmac_key = ndn_key_storage_get_hmac_key(keyid);
    if (hmac_key == NULL) {
      on_failure(&interest, on_failure_userdata);
      return;
    }
    else {
      result = ndn_signed_interest_hmac_verify(&interest, hmac_key);
      if (result == NDN_SUCCESS) on_success(&interest, on_success_userdata);
      else on_failure(&interest, on_failure_userdata);
      return;
    }
  }
  if (need_interest_out) {
    ndn_interest_t cert_interest;
    ndn_interest_init(&cert_interest);
    memcpy(&cert_interest.name, &interest.signature.key_locator_name, sizeof(ndn_name_t));
    ndn_interest_set_CanBePrefix(&cert_interest, true);
    ndn_interest_set_MustBeFresh(&cert_interest, true);
    ndn_encoder_t encoder;
    encoder_init(&encoder, verifier_buf, sizeof(verifier_buf));
    ndn_interest_tlv_encode(&encoder, &cert_interest);
    m_userdata.is_interest = true;
    m_userdata.original_pkt = (void*)&interest;
    m_userdata.on_success_cbk = on_success;
    m_userdata.on_success_userdata = on_success_userdata;
    m_userdata.on_failure_cbk = on_failure;
    m_userdata.on_failure_userdata = on_failure_userdata;
    int ret = ndn_forwarder_express_interest(encoder.output_value, encoder.offset,
                                             sig_verifier_on_data, sig_verifier_on_timeout, &m_userdata);
    if (ret == NDN_FWD_NO_ROUTE) {
      ndn_forwarder_add_route_by_name(m_sig_verifier_state.face, &cert_interest.name);
      ret = ndn_forwarder_express_interest(encoder.output_value, encoder.offset,
                                           sig_verifier_on_data, sig_verifier_on_timeout, &m_userdata);
    }
    if (ret != 0) {
      NDN_LOG_DEBUG("[SIGVERIFIER] Fail to send out cert fetch Interest. Error Code: %d\n", ret);
      on_failure(&interest, on_failure_userdata);
      return;
    }
    NDN_LOG_DEBUG("[SIGVERIFIER] Send cert fetch interest: \n");
    NDN_LOG_DEBUG_NAME(&cert_interest.name);
    return;
  }
  on_failure(&interest, on_failure_userdata);
  return;
}

void
ndn_sig_verifier_verify_data(const uint8_t* raw_pkt, size_t pkt_size,
                             on_data_verification_success on_success, void* on_success_userdata,
                             on_data_verification_failure on_failure, void* on_failure_userdata)
{
  static ndn_data_t data;
  uint32_t be_signed_start, be_signed_end;

#if ENABLE_NDN_LOG_DEBUG
  m_measure_tp1 = ndn_time_now_us();
#endif

  ndn_data_tlv_decode_no_verify(&data, raw_pkt, pkt_size, &be_signed_start, &be_signed_end);

#if ENABLE_NDN_LOG_DEBUG
  m_measure_tp2 = ndn_time_now_us();
  NDN_LOG_DEBUG("[SIGVERIFIER] DATA-PKT-DECODING: %" PRI_ndn_time_us_t "\n", m_measure_tp2 - m_measure_tp1);
#endif

  if (data.signature.sig_type < 0 || data.signature.sig_type > 4) {
    on_failure(&data, on_failure_userdata);
    return;
  }
  int result = 0;
  if (data.signature.sig_type == NDN_SIG_TYPE_DIGEST_SHA256) {
    result = ndn_sha256_verify(raw_pkt + be_signed_start, be_signed_end - be_signed_start,
                               data.signature.sig_value, data.signature.sig_size);
    if (result == NDN_SUCCESS) on_success(&data, on_success_userdata);
    else on_failure(&data, on_failure_userdata);
    return;
  }
  if (data.signature.enable_KeyLocator <= 0) {
    on_failure(&data, on_failure_userdata);
    return;
  }
  uint32_t keyid = key_id_from_key_name(&data.signature.key_locator_name);
  bool need_interest_out = false;
  if (data.signature.sig_type == NDN_SIG_TYPE_ECDSA_SHA256) {
    ndn_ecc_pub_t* pub_key = ndn_key_storage_get_ecc_pub_key(keyid);
    if (pub_key == NULL) {
      need_interest_out = true;
    }
    else {

#if ENABLE_NDN_LOG_DEBUG
  m_measure_tp1 = ndn_time_now_us();
#endif

      result = ndn_ecdsa_verify(raw_pkt + be_signed_start, be_signed_end - be_signed_start,
                                data.signature.sig_value, data.signature.sig_size, pub_key);

#if ENABLE_NDN_LOG_DEBUG
  m_measure_tp2 = ndn_time_now_us();
  NDN_LOG_DEBUG("[SIGVERIFIER] DATA-PKT-ECDSA-VERIFY: %" PRI_ndn_time_us_t "\n", m_measure_tp2 - m_measure_tp1);
#endif

      if (result == NDN_SUCCESS) on_success(&data, on_success_userdata);
      else on_failure(&data, on_failure_userdata);
      return;
    }
  }
  else if (data.signature.sig_type == NDN_SIG_TYPE_HMAC_SHA256) {
    ndn_hmac_key_t* hmac_key = ndn_key_storage_get_hmac_key(keyid);
    if (hmac_key == NULL) {
      on_failure(&data, on_failure_userdata);
      return;
    }
    else {

#if ENABLE_NDN_LOG_DEBUG
  m_measure_tp1 = ndn_time_now_us();
#endif

      result = ndn_hmac_verify(raw_pkt + be_signed_start, be_signed_end - be_signed_start,
                               data.signature.sig_value, data.signature.sig_size, hmac_key);

#if ENABLE_NDN_LOG_DEBUG
  m_measure_tp2 = ndn_time_now_us();
  NDN_LOG_DEBUG("[SIGVERIFIER] DATA-PKT-HMAC-VERIFY: %" PRI_ndn_time_us_t "\n", m_measure_tp2 - m_measure_tp1);
#endif

      if (result == NDN_SUCCESS) on_success(&data, on_success_userdata);
      else on_failure(&data, on_failure_userdata);
      return;
    }
  }
  if (need_interest_out) {
    ndn_interest_t cert_interest;
    ndn_interest_init(&cert_interest);
    memcpy(&cert_interest.name, &data.signature.key_locator_name, sizeof(ndn_name_t));
#if ENABLE_NDN_LOG_DEBUG
    NDN_LOG_DEBUG("[SIGVERIFIER] Interest Sent out from SigVerifier: ");
    NDN_LOG_DEBUG_NAME(&cert_interest.name);
#endif
    ndn_interest_set_CanBePrefix(&cert_interest, true);
    ndn_interest_set_MustBeFresh(&cert_interest, false);
    cert_interest.lifetime = 8000;
    ndn_encoder_t encoder;
    encoder_init(&encoder, verifier_buf, sizeof(verifier_buf));
    ndn_time_delay(80);
    ndn_interest_tlv_encode(&encoder, &cert_interest);
    m_userdata.is_interest = false;
    m_userdata.original_pkt = (void*)&data;
    m_userdata.on_success_cbk = on_success;
    m_userdata.on_failure_cbk = on_failure;
    m_userdata.on_success_userdata = on_success_userdata;
    ndn_forwarder_express_interest(encoder.output_value, encoder.offset,
                                   sig_verifier_on_data, sig_verifier_on_timeout, &m_userdata);
    ndn_time_delay(80);
    return;
  }
  on_failure(&data, on_failure_userdata);
  return;
}