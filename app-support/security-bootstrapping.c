/*
 * Copyright (C) 2018-2020
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN-LITE authors and contributors.
 */

#include "security-bootstrapping.h"
#include "service-discovery.h"
#include "access-control.h"
#include "ndn-sig-verifier.h"
// #include "ndn-trust-schema.h"
#include "policy.h"
#include "../encode/interest.h"
#include "../encode/signed-interest.h"
#include "../encode/data.h"
#include "../encode/key-storage.h"
#include "../ndn-error-code.h"
#include "../util/uniform-time.h"
#include "../util/msg-queue.h"
#include "../security/ndn-lite-aes.h"
#include "../security/ndn-lite-sha.h"

#define ENABLE_NDN_LOG_INFO 1
#define ENABLE_NDN_LOG_DEBUG 1
#define ENABLE_NDN_LOG_ERROR 1

#include "../util/logger.h"

typedef struct ndn_sec_boot_state {
  ndn_face_intf_t* face;
  const ndn_device_info_t* device_info;
  uint8_t trust_anchor_sha[NDN_SEC_SHA256_HASH_SIZE];
  ndn_ecc_pub_t controller_dh_pub;
  ndn_ecc_prv_t* pre_installed_ecc_key;
  ndn_hmac_key_t* pre_shared_hmac_key;
  ndn_security_bootstrapping_after_bootstrapping after_sec_boot;
  uint8_t cert_count;
} ndn_sec_boot_state_t;

static uint8_t sec_boot_buf[4096];
static ndn_sec_boot_state_t m_sec_boot_state;
static ndn_time_ms_t m_callback_after = 0;

#if ENABLE_NDN_LOG_DEBUG
static ndn_time_ms_t m_measure_tp0 = 0;
static ndn_time_us_t m_measure_tp1 = 0;
static ndn_time_us_t m_measure_tp2 = 0;
#endif

// some common rules: 1. keep keys in key_storage 2. delete the key from key storage if its not used any longer

int sec_boot_send_sign_on_interest();
int sec_boot_send_cert_interest();
void _prepare_sec_boot_send_cert_interest(ndn_interest_t* interest, uint8_t service);

void
_sec_boot_call_app_callback()
{
  if (ndn_time_now_ms() < m_callback_after) {
    ndn_msgqueue_post(NULL, _sec_boot_call_app_callback, 0, NULL);
    return;
  }
  // call application-defined after_bootstrapping function
  m_sec_boot_state.after_sec_boot();
}

void
_sec_boot_after_bootstrapping()
{
#if ENABLE_NDN_LOG_DEBUG
  NDN_LOG_DEBUG("[BOOTSTRAPPING] BOOTSTRAPPING-TOTAL-TIME: %" PRI_ndn_time_us_t "\n", ndn_time_now_ms() - m_measure_tp0);
#endif

  // start running service discovery protocol
  ndn_sd_after_bootstrapping(m_sec_boot_state.face);

  // call access control's after bootstrapping
  ndn_ac_after_bootstrapping();

  // init signature verifier
  ndn_sig_verifier_after_bootstrapping(m_sec_boot_state.face);

  // subscribe to policy update
  /*
   * Tianyuan: Will bring this back when controller's policy publishing is ready
   */
  ndn_policy_after_bootstrapping(3000);

  // we shouldn't delete the AES key because they may be used in other places
  // ndn_key_storage_delete_aes_key(SEC_BOOT_AES_KEY_ID);
  ndn_key_storage_delete_ecc_key(SEC_BOOT_DH_KEY_ID);

  NDN_LOG_INFO("[BOOTSTRAPPING]: Successfully finished NDN security bootstrapping");

  m_callback_after = ndn_time_now_ms() + 1500;
  ndn_msgqueue_post(NULL, _sec_boot_call_app_callback, 0, NULL);
}

void
on_sec_boot_sign_on_interest_timeout (void* userdata)
{
  // do nothing for now
  (void)userdata;
  NDN_LOG_INFO("[BOOTSTRAPPING]: sign on Interest timeout");
  sec_boot_send_sign_on_interest();
}

void
on_cert_data(const uint8_t* raw_data, uint32_t data_size, void* userdata)
{
  (void) userdata;
  // parse received data
  ndn_data_t data;
  if (ndn_data_tlv_decode_hmac_verify(&data, raw_data, data_size, m_sec_boot_state.pre_shared_hmac_key) != NDN_SUCCESS) {
    NDN_LOG_ERROR("[BOOTSTRAPPING]: Decoding failed.\n");
    return;
  }
  NDN_LOG_DEBUG("BOOTSTRAPPING-DATA2-PKT-SIZE: %u Bytes\n", data_size);
  NDN_LOG_INFO("[BOOTSTRAPPING]: Receive Sign On Certificate Data packet with name");
  NDN_LOG_INFO_NAME(&data.name);

  NDN_LOG_INFO("[BOOTSTRAPPING]: No.%d Certificate Received\n", ++m_sec_boot_state.cert_count);
  // parse content
  // format: self certificate, encrypted key
  ndn_decoder_t decoder;
  decoder_init(&decoder, data.content_value, data.content_size);
  // self cert certificate
  uint32_t probe = 0;
  decoder_get_type(&decoder, &probe);
  if (probe != TLV_Data) return;
  decoder_get_length(&decoder, &probe);
  decoder.offset += probe;
  ndn_data_t self_cert;
  if (ndn_data_tlv_decode_no_verify(&self_cert, data.content_value, encoder_probe_block_size(TLV_Data, probe), NULL, NULL) != NDN_SUCCESS) {
    return;
  }

#if ENABLE_NDN_LOG_DEBUG
  m_measure_tp1 = ndn_time_now_us();
#endif

  // iv
  decoder_get_type(&decoder, &probe);
  if (probe != TLV_AC_AES_IV) return;
  decoder_get_length(&decoder, &probe);
  uint8_t aes_iv[NDN_SEC_AES_IV_LENGTH];
  decoder_get_raw_buffer_value(&decoder, aes_iv, NDN_SEC_AES_IV_LENGTH);
  // encrypted private key
  decoder_get_type(&decoder, &probe);
  if (probe != TLV_AC_ENCRYPTED_PAYLOAD) return;
  decoder_get_length(&decoder, &probe);
  ndn_aes_key_t* sym_aes_key = ndn_key_storage_get_aes_key(SEC_BOOT_AES_KEY_ID);
  uint32_t used_size = 0;
  uint8_t plaintext[256] = {0};
  int ret = ndn_aes_cbc_decrypt(decoder.input_value + decoder.offset, probe,
                                plaintext, &used_size, aes_iv, sym_aes_key);

#if ENABLE_NDN_LOG_DEBUG
  m_measure_tp2 = ndn_time_now_us();
  NDN_LOG_DEBUG("[BOOTSTRAPPING] BOOTSTRAPPING-DATA2-PKT-AES-DEC: %" PRI_ndn_time_us_t "\n", m_measure_tp2 - m_measure_tp1);
#endif

  if (ret != NDN_SUCCESS) {
    NDN_LOG_ERROR("[BOOTSTRAPPING] Cannot decrypt sealed private key, Error code: %d\n", ret);
    return;
  }
  // set key storage
  ndn_ecc_prv_t self_prv;
  uint32_t keyid = key_id_from_cert_name(&self_cert.name);
  //NDN_LOG_DEBUG("cert name is: ");
  //NDN_LOG_DEBUG_NAME(&self_cert.name);
  ndn_ecc_prv_init(&self_prv, plaintext, used_size, NDN_ECDSA_CURVE_SECP256R1, keyid);
  //NDN_LOG_DEBUG("keyid is %ld\n", keyid);
  ret = ndn_key_storage_set_self_identity(&self_cert, &self_prv);
  if (ret) {
    NDN_LOG_ERROR("[BOOTSTRAPPING] Setting self identity failed, oversize");
    return;
  }
  // finish the bootstrapping process
  if (m_sec_boot_state.cert_count >= m_sec_boot_state.device_info->service_list_size)
    _sec_boot_after_bootstrapping();
}

void
on_sec_boot_cert_interest_timeout (void* userdata)
{
  // do nothing for now
  uint8_t service = *(uint8_t*)userdata;
  NDN_LOG_INFO("[BOOTSTRAPPING] %u Service Cert Interest timeout", service);
  ndn_interest_t cert_interest;
  _prepare_sec_boot_send_cert_interest(&cert_interest, service);
  ndn_encoder_t encoder;
  encoder_init(&encoder, sec_boot_buf, sizeof(sec_boot_buf));
  ndn_interest_tlv_encode(&encoder, &cert_interest);
  int ret = ndn_forwarder_express_interest(encoder.output_value, encoder.offset,
                                           on_cert_data, on_sec_boot_cert_interest_timeout,
                                           &service);
  if (ret != 0) {
    NDN_LOG_ERROR("[BOOTSTRAPPING] Fail to send out adv Interest. Error Code: %d", ret);
    return;
  }
  NDN_LOG_DEBUG("[BOOTSTRAPPING] BOOTSTRAPPING-INT2-PKT-SIZE: %u Bytes\n", encoder.offset);
  NDN_LOG_INFO("[BOOTSTRAPPING] Send SEC BOOT cert Interest packet with name");
  NDN_LOG_INFO_NAME(&cert_interest.name);
}

void
_prepare_sec_boot_send_cert_interest(ndn_interest_t* interest, uint8_t service)
{
  // generate the cert interest (2nd interest)
  ndn_interest_init(interest);
  ndn_key_storage_t* key_storage = ndn_key_storage_get_instance();

#if ENABLE_NDN_LOG_DEBUG
  m_measure_tp1 = ndn_time_now_us();
#endif

  ndn_name_append_component(&interest->name, &key_storage->trust_anchor.name.components[0]);
  ndn_name_append_string_component(&interest->name, "cert", strlen("cert"));
  // set params
  // format: name component, N2, sha2 of trust anchor, N1
  ndn_encoder_t encoder;
  encoder_init(&encoder, sec_boot_buf, sizeof(sec_boot_buf));
  // identifier name component
  ndn_name_t device_identifier_comp;
  ndn_name_from_string(&device_identifier_comp, m_sec_boot_state.device_info->device_identifier,
                       strlen(m_sec_boot_state.device_info->device_identifier));
  name_component_tlv_encode(&encoder, &device_identifier_comp.components[0]);
  // append the ecdh pub key, N2
  encoder_append_type(&encoder, TLV_SEC_BOOT_N2_ECDH_PUB);
  encoder_append_length(&encoder, ndn_ecc_get_pub_key_size(&m_sec_boot_state.controller_dh_pub));
  encoder_append_raw_buffer_value(&encoder, ndn_ecc_get_pub_key_value(&m_sec_boot_state.controller_dh_pub),
                                  ndn_ecc_get_pub_key_size(&m_sec_boot_state.controller_dh_pub));
  // append sha256 of the trust anchor
  encoder_append_type(&encoder, TLV_SEC_BOOT_ANCHOR_DIGEST);
  encoder_append_length(&encoder, NDN_SEC_SHA256_HASH_SIZE);
  encoder_append_raw_buffer_value(&encoder, m_sec_boot_state.trust_anchor_sha, NDN_SEC_SHA256_HASH_SIZE);
  // append the ecdh pub key, N1
  ndn_ecc_pub_t* self_dh_pub = ndn_key_storage_get_ecc_pub_key(SEC_BOOT_DH_KEY_ID);
  encoder_append_type(&encoder, TLV_SEC_BOOT_N1_ECDH_PUB);
  encoder_append_length(&encoder, ndn_ecc_get_pub_key_size(self_dh_pub));
  encoder_append_raw_buffer_value(&encoder, ndn_ecc_get_pub_key_value(self_dh_pub),
                                  ndn_ecc_get_pub_key_size(self_dh_pub));

  // append the device capabilities
  encoder_append_type(&encoder, TLV_SSP_DEVICE_CAPABILITIES);
  encoder_append_length(&encoder, sizeof(service));
  encoder_append_raw_buffer_value(&encoder, &service, sizeof(service));
  // set parameter
  ndn_interest_set_Parameters(interest, encoder.output_value, encoder.offset);
  // set must be fresh
  ndn_interest_set_MustBeFresh(interest, true);
  interest->lifetime = 5000;

#if ENABLE_NDN_LOG_DEBUG
  m_measure_tp2 = ndn_time_now_us();
  NDN_LOG_DEBUG("[BOOTSTRAPPING] BOOTSTRAPPING-INT2-PKT-ENCODING: %" PRI_ndn_time_us_t "\n", m_measure_tp2 - m_measure_tp1);
#endif

  // sign the interest
  ndn_signed_interest_ecdsa_sign(interest, &device_identifier_comp, m_sec_boot_state.pre_installed_ecc_key);

#if ENABLE_NDN_LOG_DEBUG
  m_measure_tp1 = ndn_time_now_us();
  NDN_LOG_DEBUG("[BOOTSTRAPPING] BOOTSTRAPPING-INT2-ECDSA-SIGN: %" PRI_ndn_time_us_t "\n", m_measure_tp1 - m_measure_tp2);
#endif

}

int
sec_boot_send_cert_interest()
{
  ndn_interest_t cert_interest;
  for (int i = 0; i < m_sec_boot_state.device_info->service_list_size; i++) {
    _prepare_sec_boot_send_cert_interest(&cert_interest,
                                         m_sec_boot_state.device_info->service_list[i]);
    ndn_encoder_t encoder;
    encoder_init(&encoder, sec_boot_buf, sizeof(sec_boot_buf));
    ndn_interest_tlv_encode(&encoder, &cert_interest);
    NDN_LOG_DEBUG("[BOOTSTRAPPING] Sending the No.%d Cert Interest\n", i + 1);
    int ret = ndn_forwarder_express_interest(encoder.output_value, encoder.offset,
                                             on_cert_data, on_sec_boot_cert_interest_timeout,
                                             &m_sec_boot_state.device_info->service_list[i]);
    if (ret != 0) {
      NDN_LOG_ERROR("[BOOTSTRAPPING] Fail to send out adv Interest. Error Code: %d\n", ret);
      return ret;
    }
    NDN_LOG_DEBUG("[BOOTSTRAPPING] BOOTSTRAPPING-INT2-PKT-SIZE: %u Bytes\n", encoder.offset);
    NDN_LOG_INFO("[BOOTSTRAPPING] Send SEC BOOT cert Interest packet with name: ");
    NDN_LOG_INFO_NAME(&cert_interest.name);

  }

  return NDN_SUCCESS;
}

void
on_sign_on_data(const uint8_t* raw_data, uint32_t data_size, void* userdata)
{
  (void) userdata;
  // parse received data
  ndn_data_t data;
  if (ndn_data_tlv_decode_hmac_verify(&data, raw_data, data_size, m_sec_boot_state.pre_shared_hmac_key) != NDN_SUCCESS) {
    NDN_LOG_ERROR("[BOOTSTRAPPING] Decoding failed.");
    return;
  }
  NDN_LOG_DEBUG("[BOOTSTRAPPING] BOOTSTRAPPING-DATA1-PKT-SIZE: %u Bytes\n", data_size);
  NDN_LOG_INFO("[BOOTSTRAPPING] Receive Sign On Data packet with name");
  NDN_LOG_INFO_NAME(&data.name);
  uint32_t probe = 0;

  // parse content
  // format: a data packet, ecdh pub, salt
  ndn_decoder_t decoder;
  decoder_init(&decoder, data.content_value, data.content_size);
  // trust anchor certificate
  decoder_get_type(&decoder, &probe);
  if (probe != TLV_Data) return;
  decoder_get_length(&decoder, &probe);
  decoder.offset += probe;
  // calculate the sha256 digest of the trust anchor
  ndn_sha256(decoder.input_value, encoder_probe_block_size(TLV_Data, probe),
             m_sec_boot_state.trust_anchor_sha);
  ndn_data_t trust_anchor_cert;
  if (ndn_data_tlv_decode_no_verify(&trust_anchor_cert, data.content_value, encoder_probe_block_size(TLV_Data, probe), NULL, NULL) != NDN_SUCCESS) {
    return;
  }
  // key storage set trust anchor
  ndn_key_storage_set_trust_anchor(&trust_anchor_cert);
  // parse ecdh pub key, N2
  decoder_get_type(&decoder, &probe);
  if (probe != TLV_SEC_BOOT_N2_ECDH_PUB) return;
  decoder_get_length(&decoder, &probe);
  uint8_t dh_pub_buf[100];
  decoder_get_raw_buffer_value(&decoder, dh_pub_buf, probe);
  ndn_ecc_pub_init(&m_sec_boot_state.controller_dh_pub, dh_pub_buf, probe, NDN_ECDSA_CURVE_SECP256R1, 1);
  ndn_ecc_prv_t* self_prv_key = ndn_key_storage_get_ecc_prv_key(SEC_BOOT_DH_KEY_ID);

#if ENABLE_NDN_LOG_DEBUG
  m_measure_tp1 = ndn_time_now_us();
#endif

  // get shared secret using DH process
  uint8_t shared[32];
  ndn_ecc_dh_shared_secret(&m_sec_boot_state.controller_dh_pub, self_prv_key, shared, sizeof(shared));

#if ENABLE_NDN_LOG_DEBUG
  m_measure_tp2 = ndn_time_now_us();
  NDN_LOG_DEBUG("[BOOTSTRAPPING] BOOTSTRAPPING-DATA1-ECDH: %" PRI_ndn_time_us_t "\n", m_measure_tp2 - m_measure_tp1);
#endif

  // decode salt from the replied data
  decoder_get_type(&decoder, &probe);
  if (probe != TLV_AC_SALT) return;
  decoder_get_length(&decoder, &probe);
  uint8_t salt[NDN_APPSUPPORT_AC_SALT_SIZE];
  decoder_get_raw_buffer_value(&decoder, salt, sizeof(salt));

#if ENABLE_NDN_LOG_DEBUG
  m_measure_tp1 = ndn_time_now_us();
#endif

  // generate AES key using HKDF
  ndn_aes_key_t* sym_aes_key = ndn_key_storage_get_empty_aes_key();
  uint8_t symmetric_key[NDN_APPSUPPORT_AC_EDK_SIZE];
  ndn_hkdf(shared, sizeof(shared), symmetric_key, sizeof(symmetric_key),
           salt, sizeof(salt), NULL, 0);
  ndn_aes_key_init(sym_aes_key, symmetric_key, sizeof(symmetric_key), SEC_BOOT_AES_KEY_ID);

#if ENABLE_NDN_LOG_DEBUG
  m_measure_tp2 = ndn_time_now_us();
  NDN_LOG_DEBUG("[BOOTSTRAPPING] BOOTSTRAPPING-DATA1-HKDF: %" PRI_ndn_time_us_t "\n", m_measure_tp2 - m_measure_tp1);
#endif

  // prepare for the next interest: register the prefix
  ndn_name_t prefix_to_register;
  ndn_name_init(&prefix_to_register);
  ndn_name_append_component(&prefix_to_register, &trust_anchor_cert.name.components[0]);
  ndn_encoder_t encoder;
  encoder_init(&encoder, sec_boot_buf, sizeof(sec_boot_buf));
  ndn_name_tlv_encode(&encoder, &prefix_to_register);
  ndn_forwarder_add_route(m_sec_boot_state.face, encoder.output_value, encoder.offset);
  // send cert interest
  ndn_time_delay(60);
  sec_boot_send_cert_interest();
}

int
sec_boot_send_sign_on_interest()
{
#if ENABLE_NDN_LOG_DEBUG
  m_measure_tp1 = ndn_time_now_us();
#endif

  int ret = 0;
  // generate the sign on interest  (1st interest)
  // make the Interest packet
  ndn_interest_t interest;
  ndn_interest_init(&interest);
  ndn_name_append_string_component(&interest.name, "ndn", strlen("ndn"));
  ndn_name_append_string_component(&interest.name, "sign-on", strlen("sign-on"));
  // make Interest parameter
  // format: a name component, a list of services provided, the EC_pub_key
  ndn_encoder_t encoder;
  encoder_init(&encoder, sec_boot_buf, sizeof(sec_boot_buf));
  // append the identifier name component
  name_component_t device_identifier_comp;
  name_component_from_string(&device_identifier_comp, m_sec_boot_state.device_info->device_identifier,
                             strlen(m_sec_boot_state.device_info->device_identifier));
  name_component_tlv_encode(&encoder, &device_identifier_comp);
  // append the capabilities
  encoder_append_type(&encoder, TLV_SEC_BOOT_CAPABILITIES);
  encoder_append_length(&encoder, m_sec_boot_state.device_info->service_list_size);
  encoder_append_raw_buffer_value(&encoder, m_sec_boot_state.device_info->service_list,
                                  m_sec_boot_state.device_info->service_list_size);
  // append the ecdh pub key, N1
  ndn_ecc_pub_t* dh_pub = ndn_key_storage_get_ecc_pub_key(SEC_BOOT_DH_KEY_ID);
  encoder_append_type(&encoder, TLV_SEC_BOOT_N1_ECDH_PUB);
  encoder_append_length(&encoder, ndn_ecc_get_pub_key_size(dh_pub));
  encoder_append_raw_buffer_value(&encoder, ndn_ecc_get_pub_key_value(dh_pub), ndn_ecc_get_pub_key_size(dh_pub));
  // set parameter
  ndn_interest_set_Parameters(&interest, encoder.output_value, encoder.offset);
  // set must be fresh
  ndn_interest_set_MustBeFresh(&interest,true);
  interest.lifetime = 5000;

#if ENABLE_NDN_LOG_DEBUG
  m_measure_tp2 = ndn_time_now_us();
  NDN_LOG_DEBUG("[BOOTSTRAPPING] BOOTSTRAPPING-INT1-PKT-ENCODING: %" PRI_ndn_time_us_t "\n", m_measure_tp2 - m_measure_tp1);
#endif

  // sign the interest
  ndn_name_t key_locator;
  ndn_name_init(&key_locator);
  ndn_name_append_component(&key_locator, &device_identifier_comp);
  ndn_signed_interest_ecdsa_sign(&interest, &key_locator, m_sec_boot_state.pre_installed_ecc_key);

#if ENABLE_NDN_LOG_DEBUG
  m_measure_tp1 = ndn_time_now_us();
  NDN_LOG_DEBUG("[BOOTSTRAPPING] BOOTSTRAPPING-INT1-PKT-ECDSA-SIGN: %" PRI_ndn_time_us_t "\n", m_measure_tp1 - m_measure_tp2);
#endif

  // send it out
  encoder_init(&encoder, sec_boot_buf, sizeof(sec_boot_buf));
  ndn_interest_tlv_encode(&encoder, &interest);
  ret = ndn_forwarder_express_interest(encoder.output_value, encoder.offset,
                                       on_sign_on_data, on_sec_boot_sign_on_interest_timeout, NULL);
  if (ret != 0) {
    NDN_LOG_ERROR("[BOOTSTRAPPING] Fail to send out adv Interest. Error Code: %d", ret);
    return ret;
  }
  NDN_LOG_DEBUG("[BOOTSTRAPPING] BOOTSTRAPPING-INT1-PKT-SIZE: %u Bytes\n", encoder.offset);
  NDN_LOG_INFO("[BOOTSTRAPPING] Send SEC BOOT sign on Interest packet with name");
  NDN_LOG_INFO_NAME(&interest.name);
  return NDN_SUCCESS;
}

int
ndn_security_bootstrapping(ndn_face_intf_t* face,
                           const ndn_bootstrapping_info_t* bootstrapping_info,
                           const ndn_device_info_t* device_info,
                           ndn_security_bootstrapping_after_bootstrapping after_bootstrapping)
{
  // set ECC RNG backend
  ndn_rng_backend_t* rng_backend = ndn_rng_get_backend();
  int ret = ndn_ecc_set_rng(rng_backend->rng);
  if (ret != NDN_SUCCESS) return ret;

  // load pre-installed keys
  ndn_ecc_prv_t* ecc_secp256r1_prv_key;
  ndn_ecc_pub_t* ecc_secp256r1_pub_key;
  ndn_key_storage_get_empty_ecc_key(&ecc_secp256r1_pub_key, &ecc_secp256r1_prv_key);
  ret = ndn_ecc_prv_init(ecc_secp256r1_prv_key, bootstrapping_info->pre_installed_prv_key_bytes,
                         SEC_BOOT_PRE_ECC_PRV_KEY_SIZE, NDN_ECDSA_CURVE_SECP256R1, SEC_BOOT_PRE_ECC_KEY_ID);
  if (ret != NDN_SUCCESS) return ret;
  ret = ndn_ecc_pub_init(ecc_secp256r1_pub_key, bootstrapping_info->pre_installed_pub_key_bytes,
                         SEC_BOOT_PRE_ECC_PUB_KEY_SIZE, NDN_ECDSA_CURVE_SECP256R1, SEC_BOOT_PRE_ECC_KEY_ID);
  if (ret != NDN_SUCCESS) return ret;
  ndn_hmac_key_t* hmac_key = ndn_key_storage_get_empty_hmac_key();
  ret = ndn_hmac_key_init(hmac_key, bootstrapping_info->pre_shared_hmac_key_bytes,
                          SEC_BOOT_PRE_HMAC_KEY_SIZE, SEC_BOOT_PRE_HMAC_KEY_ID);
  if (ret != NDN_SUCCESS) return ret;
  m_sec_boot_state.pre_installed_ecc_key = ecc_secp256r1_prv_key;
  m_sec_boot_state.pre_shared_hmac_key = hmac_key;

  // remember the state for future use
  m_sec_boot_state.face = face;
  m_sec_boot_state.device_info = device_info;
  m_sec_boot_state.after_sec_boot = after_bootstrapping;

  // preparation
  ndn_ecc_pub_t* dh_pub = NULL;
  ndn_ecc_prv_t* dh_prv = NULL;
  ndn_key_storage_get_empty_ecc_key(&dh_pub, &dh_prv);

#if ENABLE_NDN_LOG_DEBUG
  m_measure_tp1 = ndn_time_now_us();
#endif

  ret = ndn_ecc_make_key(dh_pub, dh_prv, NDN_ECDSA_CURVE_SECP256R1, SEC_BOOT_DH_KEY_ID);
  if (ret != NDN_SUCCESS) return ret;

#if ENABLE_NDN_LOG_DEBUG
  m_measure_tp2 = ndn_time_now_us();
  NDN_LOG_DEBUG("[BOOTSTRAPPING] BOOTSTRAPPING-INT1-ECDH-KEYGEN: %" PRI_ndn_time_us_t "\n", m_measure_tp2 - m_measure_tp1);
#endif

  // register route
  ret = ndn_forwarder_add_route_by_str(face, "/ndn/sign-on", strlen("/ndn/sign-on"));
  if (ret != NDN_SUCCESS) return ret;
  NDN_LOG_INFO("[BOOTSTRAPPING] Successfully add route");

#if ENABLE_NDN_LOG_DEBUG
  m_measure_tp0 = ndn_time_now_ms();
#endif

  // send the first interest out
  sec_boot_send_sign_on_interest();
  return NDN_SUCCESS;
}