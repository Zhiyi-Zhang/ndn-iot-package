/*
 * Copyright (C) 2018-2020
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN-LITE authors and contributors.
 */

#include "access-control.h"
#include "security-bootstrapping.h"
#include "../ndn-services.h"
#include "../ndn-error-code.h"
#include "../encode/key-storage.h"
#include "../encode/signed-interest.h"
#include "../encode/encrypted-payload.h"
#include "../forwarder/forwarder.h"
#include "../security/ndn-lite-aes.h"
#include "../security/ndn-lite-ecc.h"
#include "../security/ndn-lite-hmac.h"
#include "../security/ndn-lite-rng.h"
#include "../util/msg-queue.h"
#include "../util/uniform-time.h"

#include <inttypes.h>

#define KEY_LIFTIME 60000

/* Logging Level: ERROR, DEBUG */
#define ENABLE_NDN_LOG_ERROR 1
#define ENABLE_NDN_LOG_DEBUG 1
#include "../util/logger.h"

#if ENABLE_NDN_LOG_DEBUG
static ndn_time_us_t m_measure_tp1 = 0;
static ndn_time_us_t m_measure_tp2 = 0;
#endif

/* Encoding buffer for Access Control module */
static uint8_t ac_buf[1024];

/**
 * The structure of AccessControlKey.
 */
typedef struct ac_key {
  /**
   * KeyID, should be globally unique in KeyStorage.
   */
  uint32_t key_id;
  /**
   * KeyLifetime, the key expiration time is Now + KeyLifetime.
   */
  uint64_t expires_at;
  /**
   * InRenewal, indicating if this key is in renewal process
   */
  bool in_renewal;
} ac_key_t;

/**
 * The structure of AccessControlState.
 */
typedef struct ndn_access_control {
  /**
   * AccessServices for this identity that would use DecryptionKey.
   */
  uint8_t access_services[10];
  /**
   * DecryptionKeys used for by identity's AccessService.
   */
  ac_key_t access_keys[10];
  /**
   * RegisterServices for this identity that would use EncryptionKey.
   */
  uint8_t self_services[10];
  /**
   * EncryptionKeys used for by identity's RegisterServices.
   */
  ac_key_t ekeys[10];
} ndn_access_control_t;

ndn_access_control_t _ac_self_state;
bool _ac_initialized = false;

int _express_dkey_interest(uint8_t service);
int _express_ekey_interest(uint8_t service);

/* Initialize the AccessControlState */
void
_init_ac_state()
{
  for (int i = 0; i < 10; i++) {
    _ac_self_state.access_keys[i].key_id = NDN_SEC_INVALID_KEY_ID;
    _ac_self_state.access_keys[i].in_renewal = false;
    _ac_self_state.access_services[i] = NDN_SD_NONE;
  }
  for (int i = 0; i < 10; i++) {
    _ac_self_state.ekeys[i].key_id = NDN_SEC_INVALID_KEY_ID;
    _ac_self_state.access_keys[i].in_renewal = false;
    _ac_self_state.self_services[i] = NDN_SD_NONE;
  }
  _ac_initialized = true;
}

void
_ac_timeout()
{
  ndn_time_ms_t now = ndn_time_now_ms();
  if (!_ac_initialized) {
    NDN_LOG_ERROR("[ACCESSCTL] Access Control module not initialized\n");
  }
  for (int i = 0; i < 10; i++) {
    if (_ac_self_state.access_keys[i].key_id != NDN_SEC_INVALID_KEY_ID &&
        _ac_self_state.access_keys[i].in_renewal == false &&
        now > _ac_self_state.access_keys[i].expires_at) {
          NDN_LOG_DEBUG("[ACCESSCTL] Now is %" PRI_ndn_time_us_t ", Expiration time is %" PRI_ndn_time_us_t "\n", now, _ac_self_state.access_keys[i].expires_at);
          NDN_LOG_DEBUG("[ACCESSCTL] Access key for for service %u expired\n", _ac_self_state.access_services[i]);
          // send the dk renew request
          _express_dkey_interest(_ac_self_state.access_services[i]);
          _ac_self_state.access_keys[i].in_renewal = true;
        }
    if (_ac_self_state.ekeys[i].key_id != NDN_SEC_INVALID_KEY_ID &&
        _ac_self_state.ekeys[i].in_renewal == false &&
        now > _ac_self_state.ekeys[i].expires_at) {
          NDN_LOG_DEBUG("[ACCESSCTL] Now is %" PRI_ndn_time_us_t ", Expiration time is %" PRI_ndn_time_us_t "\n", now, _ac_self_state.ekeys[i].expires_at);
          NDN_LOG_DEBUG("[ACCESSCTL] Encryption key for for service %u expired\n", _ac_self_state.self_services[i]);
          // send the ek renew request
          _express_ekey_interest(_ac_self_state.self_services[i]);
          _ac_self_state.ekeys[i].in_renewal = true;
        }
  }

  ndn_msgqueue_post(NULL, _ac_timeout, 0, NULL);
}

int
_on_ac_notification(const uint8_t* interest, uint32_t interest_size, void* userdata)
{
  (void) userdata;
  ndn_interest_t notification;
  ndn_interest_from_block(&notification, interest, interest_size);
  // /[home-prefix]/NDN_SD_AC/NOTIFY/[service-id]/keyid
  NDN_LOG_DEBUG("[ACCESSCTL] Notification: ");
  NDN_LOG_DEBUG_NAME(&notification.name);

  ndn_aes_key_t* key = ndn_ac_get_key_for_service(notification.name.components[3].value[0]);
  uint32_t keyid;
  ndn_decoder_t decoder;
  decoder_init(&decoder, notification.name.components[4].value, notification.name.components[4].size);
  decoder_get_uint32_value(&decoder, &keyid);
  if (key && key->key_id <= keyid) {
      NDN_LOG_DEBUG("[ACCESSCTL] Enforced update for Service %" PRIu32 ", KeyID %" PRIu32 "\n",
      notification.name.components[3].value[0], keyid);
      for (int i = 0; i < 10; i++) {
        if (_ac_self_state.self_services[i] == notification.name.components[3].value[0])
          _express_ekey_interest(notification.name.components[3].value[0]);
        if (_ac_self_state.access_services[i] == notification.name.components[3].value[0])
          _express_dkey_interest(notification.name.components[3].value[0]);
      }
  }

  return NDN_SUCCESS;
}

/**
 *  Response for EncryptionKey onData.
 *  This will parse the EncryptionKey Data with KeyID SEC_BOOT_AES_KEY_ID Key, which is already
 *  generated from Bootstrapping. The EncryptionKey's expiration time will be calculated.
 *  Decoded EncryptionKey will be stored at KeyStorage with KeyID filled with a uint32_t random number.
 */
void
_on_ekey_data(const uint8_t* raw_data, uint32_t data_size, void* userdata)
{
  (void) userdata;
  // parse Data
  ndn_data_t data;
  int ret = -1;

  // should verify with TrustAnchor Key
  ndn_key_storage_t* storage = ndn_key_storage_get_instance();
  ret = ndn_data_tlv_decode_ecdsa_verify(&data, raw_data, data_size, &storage->trust_anchor_key);
  if (ret) {
    NDN_LOG_ERROR("[ACCESSCTL] EncryptionKey Data Verification failure, ErrorCode = %d\n", ret);
  }

  NDN_LOG_DEBUG("[ACCESSCTL] Receive EncryptionKey Data with Name: ");
  NDN_LOG_DEBUG_NAME(&data.name);

  // get key: decrypt the key
  uint32_t expires_in;
  uint32_t keyid;
  uint8_t value[50] = {0};
  uint32_t used_size = 0;
  ret = ndn_parse_encrypted_payload(data.content_value, data.content_size,
                                    value, &used_size, SEC_BOOT_AES_KEY_ID);
  if (ret || used_size == 0) {
    NDN_LOG_ERROR("[ACCESSCTL] Parse encrypted payload failure. ErrorCode = %d\n", ret);
  }

  ndn_decoder_t decoder;
  uint32_t probe;
  decoder_init(&decoder, value + NDN_AES_BLOCK_SIZE, used_size - NDN_AES_BLOCK_SIZE);
  decoder_get_type(&decoder, &probe);
  if (probe != TLV_AC_KEYID) {
    NDN_LOG_ERROR("[ACCESSCTL] TLV Type (should be TLV_AC_KEYID) not correct \n");
    return;
  }
  decoder_get_length(&decoder, &probe);
  ret = decoder_get_uint32_value(&decoder, &keyid);
  if (ret) {
    NDN_LOG_ERROR("[ACCESSCTL] Cannot get the AES KeyID, Error code is %d\n", ret);
    return;
  }
  NDN_LOG_DEBUG("[ACCESSCTL] AES KeyID = %" PRIu32 "\n", keyid);

  // set lifetime
  expires_in = KEY_LIFTIME;
  // if exist the same key, renew the payload
  uint8_t service;
  memcpy(&service, &data.name.components[3].value, sizeof(service));
  ndn_aes_key_t* ekey = ndn_ac_get_key_for_service(service);
  ndn_time_ms_t now = ndn_time_now_ms();
  if (ekey) {
    NDN_LOG_DEBUG("[ACCESSCTL] Update KeyID for service %u\n", service);
    for (int i = 0; i < 10; i++) {
      if (_ac_self_state.self_services[i] == service) {
        _ac_self_state.ekeys[i].key_id = keyid;
        _ac_self_state.ekeys[i].expires_at = expires_in + now;
        NDN_LOG_DEBUG("[ACCESSCTL] New expiration time is %" PRI_ndn_time_us_t ", New keyid is %u\n",
                      _ac_self_state.ekeys[i].expires_at, _ac_self_state.ekeys[i].key_id);
        ndn_aes_key_init(ekey, value, NDN_AES_BLOCK_SIZE, _ac_self_state.ekeys[i].key_id);
        _ac_self_state.ekeys[i].in_renewal = false;
      }
    }
  }
  else {
    NDN_LOG_DEBUG("[ACCESSCTL] Cannot find keys for service %u, might be the first time\n", service);
    // store it into key_storage
    uint8_t service = data.name.components[3].value[0];
    for (int i = 0; i < 10; i++) {
      if (_ac_self_state.self_services[i] == service) {
        _ac_self_state.ekeys[i].key_id = keyid;
        _ac_self_state.ekeys[i].in_renewal = false;
        _ac_self_state.ekeys[i].expires_at = expires_in + now;
        NDN_LOG_DEBUG("[ACCESSCTL] Expires at %" PRI_ndn_time_us_t " ms\n", _ac_self_state.ekeys[i].expires_at);
        break;
      }
    }
    ndn_aes_key_t* key = ndn_key_storage_get_empty_aes_key();
    if (key != NULL) {
      ndn_aes_key_init(key, value, NDN_AES_BLOCK_SIZE, keyid);
    }
    else {
      NDN_LOG_ERROR("[ACCESSCTL] No empty AES key in local key storage\n");
    }
  }
#if ENABLE_NDN_LOG_DEBUG
  m_measure_tp2 = ndn_time_now_us();
  NDN_LOG_DEBUG("[ACCESSCTL] Key update: %" PRI_ndn_time_us_t "ms\n", m_measure_tp2 - m_measure_tp1);
#endif

 // _ac_timeout();
}

/**
 *  Response for DecryptionKey onData.
 *  This will parse the DecryptionKey Data with KeyID SEC_BOOT_AES_KEY_ID Key, which is already
 *  generated from Bootstrapping. The DecryptionKey's expiration time will be calculated.
 *  Decoded DecryptionKey will be stored at KeyStorage with KeyID filled with a uint32_t random number.
 */
void
_on_dkey_data(const uint8_t* raw_data, uint32_t data_size, void* userdata)
{
  (void) userdata;
  // parse Data
  ndn_data_t data;
  int ret = -1;

  // should verify with TrustAnchor Key
  ndn_key_storage_t* storage = ndn_key_storage_get_instance();
  ret = ndn_data_tlv_decode_ecdsa_verify(&data, raw_data, data_size, &storage->trust_anchor_key);
  if (ret) {
    NDN_LOG_ERROR("[ACCESSCTL] DecryptionKey Data Verification failure, ErrorCode = %d\n", ret);
  }

  NDN_LOG_DEBUG("[ACCESSCTL] Receive DecryptionKey Data with Name: ");
  NDN_LOG_DEBUG_NAME(&data.name);

  // get key: decrypt the key
  uint32_t expires_in = 0;
  uint32_t keyid;
  uint8_t value[50] = {0};
  uint32_t used_size = 0;

  ret = ndn_parse_encrypted_payload(data.content_value, data.content_size,
                                    value, &used_size, SEC_BOOT_AES_KEY_ID);
  if (ret || used_size == 0) {
    NDN_LOG_ERROR("[ACCESSCTL] Parse encrypted payload failure. ErrorCode = %d\n", ret);
  }

  ndn_decoder_t decoder;
  uint32_t probe;
  decoder_init(&decoder, value + NDN_AES_BLOCK_SIZE, used_size - NDN_AES_BLOCK_SIZE);
  decoder_get_type(&decoder, &probe);
  if (probe != TLV_AC_KEYID) {
    NDN_LOG_ERROR("[ACCESSCTL] TLV Type (should be TLV_AC_KEYID) not correct \n");
    return;
  }
  decoder_get_length(&decoder, &probe);
  ret = decoder_get_uint32_value(&decoder, &keyid);
  if (ret) {
    NDN_LOG_ERROR("[ACCESSCTL] Cannot get the AES KeyID, Error code is %d\n", ret);
    return;
  }
  NDN_LOG_DEBUG("[ACCESSCTL] AES KeyID = %" PRIu32 " \n", keyid);

  // set lifetime to 3000ms
  expires_in = KEY_LIFTIME;
  // if exist the same key, renew the payload
  uint8_t service;
  memcpy(&service, &data.name.components[3].value, sizeof(service));
  ndn_aes_key_t* access_key = ndn_ac_get_key_for_service(service);
  ndn_time_ms_t now = ndn_time_now_ms();
  if (access_key) {
    NDN_LOG_DEBUG("[ACCESSCTL] Update KeyID for service %u\n", service);
    for (int i = 0; i < 10; i++) {
      if (_ac_self_state.access_services[i] == service) {
        _ac_self_state.ekeys[i].key_id = keyid;
        _ac_self_state.access_keys[i].expires_at = expires_in + now;
        NDN_LOG_DEBUG("[ACCESSCTL] New expiration time is %" PRI_ndn_time_us_t ", New keyid is %u\n",
                      _ac_self_state.access_keys[i].expires_at, _ac_self_state.access_keys[i].key_id);
        ndn_aes_key_init(access_key, value, NDN_AES_BLOCK_SIZE, _ac_self_state.access_keys[i].key_id);
        _ac_self_state.access_keys[i].in_renewal = false;
      }
    }
  }
  else {
    NDN_LOG_DEBUG("[ACCESSCTL] Cannot find keys for service %u, might be the first time\n", service);
    // store it into key_storage
    uint8_t service = data.name.components[3].value[0];
    for (int i = 0; i < 10; i++) {
      if (_ac_self_state.access_services[i] == service) {
        _ac_self_state.access_keys[i].key_id = keyid;
        _ac_self_state.access_keys[i].in_renewal = false;
        _ac_self_state.access_keys[i].expires_at = expires_in + now;
        NDN_LOG_DEBUG("[ACCESSCTL] Expires at %" PRI_ndn_time_us_t " ms\n", _ac_self_state.access_keys[i].expires_at);
        break;
      }
    }
    ndn_aes_key_t* key = ndn_key_storage_get_empty_aes_key();
    if (key != NULL) {
      ndn_aes_key_init(key, value, NDN_AES_BLOCK_SIZE, keyid);
    }
    else {
      NDN_LOG_ERROR("[ACCESSCTL] No empty AES key in local key storage\n");
    }
  }
  //_ac_timeout();
}

void
_on_ekey_int_timeout(void* userdata)
{
  NDN_LOG_DEBUG("[ACCESSCTL] EKEY interest timeout. Resend the Interest.");
  uint8_t service_id = *(uint8_t*)userdata;
  _express_ekey_interest(service_id);
}

void
_on_dkey_int_timeout(void* userdata)
{
  NDN_LOG_DEBUG("[ACCESSCTL] DKEY interest timeout. Resend the Interest.");
  uint8_t service_id = *(uint8_t*)userdata;
  _express_dkey_interest(service_id);
}

/**
 *  EncryptionKey Interesing expressing.
 *  This will express a signed Interest with CanBePrefix flag set.
 */
int
_express_ekey_interest(uint8_t service)
{
  int ret = 0;
  ndn_interest_t interest;
  ndn_interest_init(&interest);
  ndn_key_storage_t* storage = ndn_key_storage_get_instance();
  ret = ndn_name_append_component(&interest.name, &storage->self_identity[0].components[0]);
  if (ret != 0) return ret;
  uint8_t ac = NDN_SD_AC;
  ret = ndn_name_append_bytes_component(&interest.name, &ac, 1);
  if (ret != 0) return ret;
  uint8_t ekey = NDN_SD_AC_EK;
  ret = ndn_name_append_bytes_component(&interest.name, &ekey, 1);
  if (ret != 0) return ret;
  ret = ndn_name_append_bytes_component(&interest.name, &service, 1);
  if (ret != 0) return ret;

  // signature signing
  ndn_name_t* self_identity = ndn_key_storage_get_self_identity(service);
  ndn_ecc_prv_t* self_identity_key = ndn_key_storage_get_self_identity_key(service);
  if (self_identity == NULL || self_identity_key == NULL) {
    NDN_LOG_ERROR("[ACCESSCTL] Cannot find proper identity to sign");
    return NDN_AC_KEY_NOT_FOUND;
  }
  ndn_signed_interest_ecdsa_sign(&interest, self_identity, self_identity_key);

  // Express Interest
  ndn_encoder_t encoder;
  encoder_init(&encoder, ac_buf, sizeof(ac_buf));
  ndn_interest_set_CanBePrefix(&interest, true);
  ndn_interest_set_MustBeFresh(&interest, true);
  ret = ndn_interest_tlv_encode(&encoder, &interest);
  if (ret != 0) return ret;
  static uint8_t service_id = 0;
  service_id = service;
  ret = ndn_forwarder_express_interest(encoder.output_value, encoder.offset, _on_ekey_data, _on_ekey_int_timeout, &service_id);
  if (ret != 0) {
    NDN_LOG_ERROR("[ACCESSCTL] Fail to send out adv Interest. Error Code: %d\n", ret);
    return ret;
  }
  NDN_LOG_DEBUG("[ACCESSCTL] Send EncryptionKey Interest with Name: ");
  NDN_LOG_DEBUG_NAME(&interest.name);
#if ENABLE_NDN_LOG_DEBUG
  m_measure_tp1 = ndn_time_now_us();
#endif
  return NDN_SUCCESS;
}

/**
 *  DecryptionKey Interesing expressing.
 *  This will express a signed Interest with CanBePrefix flag set.
 */
int
_express_dkey_interest(uint8_t service)
{
  int ret = -1;
  ndn_interest_t interest;
  ndn_interest_init(&interest);
  ndn_key_storage_t* storage = ndn_key_storage_get_instance();
  ret = ndn_name_append_component(&interest.name, &storage->self_identity[0].components[0]);
  if (ret != 0) return ret;
  uint8_t ac = NDN_SD_AC;
  ret = ndn_name_append_bytes_component(&interest.name, &ac, 1);
  if (ret != 0) return ret;
  uint8_t dkey = NDN_SD_AC_DK;
  ret = ndn_name_append_bytes_component(&interest.name, &dkey, 1);
  if (ret != 0) return ret;
  ret = ndn_name_append_bytes_component(&interest.name, &service, 1);
  if (ret != 0) return ret;

  // TODO: figure out a better way to sign instead of using the first cert
  ndn_signed_interest_ecdsa_sign(&interest, &storage->self_identity[0], &storage->self_identity_key[0]);

  // Express Interest
  ndn_encoder_t encoder;
  encoder_init(&encoder, ac_buf, sizeof(ac_buf));
  ndn_interest_set_CanBePrefix(&interest, true);
  ndn_interest_set_MustBeFresh(&interest, true);
  ret = ndn_interest_tlv_encode(&encoder, &interest);
  if (ret != 0) return ret;
  static uint8_t service_id = 0;
  service_id = service;
  ret = ndn_forwarder_express_interest(encoder.output_value, encoder.offset, _on_dkey_data, _on_dkey_int_timeout, &service_id);
  if (ret != 0) {
    NDN_LOG_ERROR("[ACCESSCTL] Fail to send out adv Interest. Error Code: %d\n", ret);
    return ret;
  }
  NDN_LOG_DEBUG("[ACCESSCTL] Send DecryptionKey Interest with Name: ");
  NDN_LOG_DEBUG_NAME(&interest.name);
  return NDN_SUCCESS;
}

/**
 *  RegisterServices.
 */
ndn_aes_key_t*
ndn_ac_get_key_for_service(uint8_t service)
{
  for (int i = 0; i < 10; i++) {
    if (_ac_self_state.self_services[i] == service &&
        _ac_self_state.ekeys[i].key_id != NDN_SEC_INVALID_KEY_ID) {
      return ndn_key_storage_get_aes_key(_ac_self_state.ekeys[i].key_id);
    }
    if (_ac_self_state.access_services[i] == service &&
        _ac_self_state.access_keys[i].key_id != NDN_SEC_INVALID_KEY_ID) {
      return ndn_key_storage_get_aes_key(_ac_self_state.access_keys[i].key_id);
    }
  }
  return NULL;
}

/**
 *  RegisterServices.
 */
void
ndn_ac_register_encryption_key_request(uint8_t service)
{
  if (!_ac_initialized) {
    _init_ac_state();
  }
  for (int i = 0; i < 10; i++) {
    if (_ac_self_state.self_services[i] == NDN_SD_NONE) {
      _ac_self_state.self_services[i] = service;
      return;
    }
  }
}

/**
 *  AccessServices.
 */
void
ndn_ac_register_access_request(uint8_t service)
{
  if (!_ac_initialized) {
    _init_ac_state();
  }
  for (int i = 0; i < 10; i++) {
    if (_ac_self_state.access_services[i] == NDN_SD_NONE) {
      _ac_self_state.access_services[i] = service;
      return;
    }
  }
}

/**
 *  AccessControl start. Should be called after Bootstrapping.
 */
void
ndn_ac_after_bootstrapping()
{
  if (!_ac_initialized) {
    _init_ac_state();
  }
  // send /home/AC/EKEY/<the service provided by my self> to the controller
  for (int i = 0; i < 10; i++) {
    if (_ac_self_state.self_services[i] != NDN_SD_NONE) {
      _express_ekey_interest(_ac_self_state.self_services[i]);
    }
  }
  ndn_time_delay(10);
  // send /home/AC/DKEY/<the services that I need to access> to the controller
  for (int i = 0; i < 10; i++) {
    if (_ac_self_state.access_services[i] != NDN_SD_NONE) {
      _express_dkey_interest(_ac_self_state.access_services[i]);
    }
  }
  // e.g. Temp sensor produce under TEMP, access SD
  // 1. send /home/AC/EKEY/TEMP to obtain encryption key
  // 2. send /home/AC/DKEY/SD to obtain decryption key

  // register for notification interest
  ndn_name_t name;
  ndn_name_init(&name);
  ndn_key_storage_t* storage = ndn_key_storage_get_instance();
  int ret = -1;
  ret = ndn_name_append_component(&name, &storage->self_identity[0].components[0]);
    NDN_LOG_ERROR_NAME(&name);
  if (ret != 0) return;
  uint8_t ac = NDN_SD_AC;
  ret = ndn_name_append_bytes_component(&name, &ac, 1);

  // ret = ndn_name_append_string_component(&name, "AC", strlen("AC"));
  // if (ret != 0) return;
  ret = ndn_name_append_string_component(&name, "NOTIFY", strlen("NOTIFY"));
  if (ret != 0) return;
  ret = ndn_forwarder_register_name_prefix(&name, _on_ac_notification, NULL);
  NDN_LOG_ERROR_NAME(&name);
  if (ret != 0) {
    NDN_LOG_ERROR("[ACCESSCTL] Cannot register notification prefix: ");
    NDN_LOG_ERROR_NAME(&name);
  }
  _ac_timeout();
}

int
ndn_ac_trigger_expiration(uint8_t service, uint32_t received_keyid)
{
  int ret = -1;
  // check if it's a local key
  ndn_aes_key_t* aes_key = ndn_ac_get_key_for_service(service);
  if (aes_key->key_id < received_keyid) {
    NDN_LOG_DEBUG("[ACCESSCTL] Local Decryption Key %" PRIu32 " forced expired\n", aes_key->key_id);
    _express_dkey_interest(service);
  }
  else {
    NDN_LOG_DEBUG("[ACCESSCTL] Notifying Encryption Key %" PRIu32 " forced expired\n", received_keyid);
    ndn_interest_t interest;
    ndn_interest_init(&interest);
    ndn_key_storage_t* storage = ndn_key_storage_get_instance();
    ret = ndn_name_append_component(&interest.name, &storage->self_identity[0].components[0]);
    if (ret != 0) return ret;
    uint8_t ac = NDN_SD_AC;
    ret = ndn_name_append_bytes_component(&interest.name, &ac, 1);
    if (ret != 0) return ret;
    ret = ndn_name_append_string_component(&interest.name, "NOTIFY", strlen("NOTIFY"));
    if (ret != 0) return ret;
    ret = ndn_name_append_bytes_component(&interest.name, &service, 1);
    if (ret != 0) return ret;
    ret = ndn_name_append_keyid(&interest.name, received_keyid);
    if (ret != 0) return ret;
    ret = ndn_forwarder_express_interest_struct(&interest, NULL, NULL, NULL);
    if (ret != 0) return ret;
  }

  return NDN_SUCCESS;
}