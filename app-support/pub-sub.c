/*
 * Copyright (C) 2018-2020
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN-LITE authors and contributors.
 */

#include "pub-sub.h"
#include "service-discovery.h"
#include "ndn-sig-verifier.h"
#include "access-control.h"
#include "ndn-trust-schema.h"
#include "../encode/encrypted-payload.h"
#include "../ndn-constants.h"
#include "../ndn-services.h"
#include "../encode/key-storage.h"
#include "../encode/wrapper-api.h"
#include "../forwarder/forwarder.h"

#define ENABLE_NDN_LOG_INFO 1
#define ENABLE_NDN_LOG_DEBUG 1
#define ENABLE_NDN_LOG_ERROR 1

#include "../util/logger.h"

#define NDN_PUBSUB_TOPIC_SIZE 10
#define NDN_PUBSUB_MAC_TIMEOUT 2

#define PUB  1
#define SUB  2
#define MATCH_SHORT 1
#define MATCH_LONG  0
#define DATA 0
#define CMD 1

/** The struct to keep each topic subscribed.
 */
typedef struct sub_topic {
  /** Service ID
   */
  uint8_t service;
  /** Type of expected Data, can be either CMD or DATA
   */
  bool is_cmd;
  /** Identifier. Should be 0 - 2 NameComponents.
   */
  name_component_t identifier[NDN_PUBSUB_IDENTIFIER_SIZE];
  /** Interval. Time Interval between two Subscription Interest.
   */
  uint32_t interval;
  /** The time to send the next Subscription Interest.
   */
  uint64_t next_interest;
  /** On DATA/CMD publish callback.
   */
  ps_on_published callback;
  /** User defined data.
   */
  void* userdata;
  /** Decryption Key ID
   */
  uint32_t decryption_key;
  /** Last Received Packet Digest.
   */
  uint8_t last_digest[16];
  /** Has received content or not.
   */
  bool received_content;
} sub_topic_t;

/** The struct to keep each topic published.
 */
typedef struct pub_topic {
  /** Service ID
   */
  uint8_t service;
  /** Type of expected Data, can be either CMD or DATA
   */
  bool is_cmd;
  /** Cache of the lastest published DATA. If the entry is about a subscription record,
   * cache here will not be used.
   */
  uint8_t cache[300];
  /** Cached Data Size.
   */
  uint32_t cache_size;
  /** The timestamp of last update.
   */
  uint64_t last_update_tp;
  /** Decryption Key ID
   */
  uint32_t decryption_key;
} pub_topic_t;

/** The struct to keep registered topics
 */
typedef struct pub_sub_state {
  /** Topic List
   */
  sub_topic_t sub_topics[5];
  /** Topic List
   */
  pub_topic_t pub_topics[5];
  /** Minimal Interval in the Topic List. Currently not used.
   */
  uint32_t min_interval;
  /** Timepoint for the next fetching
   */
  ndn_time_ms_t m_next_send;
} pub_sub_state_t;

static uint8_t pkt_encoding_buf[512];
static pub_sub_state_t m_pub_sub_state;
static bool m_has_initialized = false;
static bool m_is_my_own_int = false;

#if ENABLE_NDN_LOG_DEBUG
static ndn_time_us_t m_measure_tp1 = 0;
static ndn_time_us_t m_measure_tp2 = 0;
#endif

/** Helper function to initialize the topic List
 */
void
_ps_topics_init()
{
  for (int i = 0; i < 5; i++) {
    m_pub_sub_state.sub_topics[i].service = NDN_SD_NONE;
    m_pub_sub_state.sub_topics[i].identifier[0].size = NDN_FWD_INVALID_NAME_COMPONENT_SIZE;
    m_pub_sub_state.sub_topics[i].identifier[1].size = NDN_FWD_INVALID_NAME_COMPONENT_SIZE;
    m_pub_sub_state.sub_topics[i].callback = NULL;
    m_pub_sub_state.sub_topics[i].next_interest = 0;
    m_pub_sub_state.sub_topics[i].received_content = false;

    m_pub_sub_state.pub_topics[i].service = NDN_SD_NONE;
  }
  m_pub_sub_state.m_next_send = 0;
  m_pub_sub_state.min_interval = 1000*60*60;
  m_has_initialized = true;
}

/** Helper function to to perform sub Topic matching.
 */
sub_topic_t*
_match_sub_topic(uint8_t service, bool is_cmd)
{
  sub_topic_t* entry = NULL;
  for (int i = 0; i < 5; i++) {
    if (m_pub_sub_state.sub_topics[i].service == service && m_pub_sub_state.sub_topics[i].is_cmd == is_cmd) {
      entry = &m_pub_sub_state.sub_topics[i];
    }
  }
  return entry;
}

/** Helper function to to perform pub Topic matching.
 */
pub_topic_t*
_match_pub_topic(uint8_t service, bool is_cmd)
{
  pub_topic_t* entry = NULL;
  for (int i = 0; i < 5; i++) {
    if (m_pub_sub_state.pub_topics[i].service == service && m_pub_sub_state.pub_topics[i].is_cmd == is_cmd) {
      entry = &m_pub_sub_state.pub_topics[i];
    }
  }
  return entry;
}

/** Ontimeout callback to indicating a Subscription Interest timout. Simply logging the timeout event.
 */
void
_on_sub_timeout(void* userdata)
{
  (void) userdata;
  NDN_LOG_INFO("[PUB/SUB] Subscription Interest Timeout");
}

void
_on_new_content_verify_success(ndn_data_t* data, void* userdata)
{
  NDN_LOG_INFO("[PUB/SUB] New published content successfully pass signature verification.");
  NDN_LOG_INFO_NAME(&data->name);

  int ret = NDN_SUCCESS;
  sub_topic_t* topic = (sub_topic_t*)userdata;
  // call the on_content callbackclear
  if (topic->callback == NULL) {
    return;
  }
  int comp_size = 0;
  for (int i = 0; i < 2; i++) {
    if (topic->identifier[i].size != NDN_FWD_INVALID_NAME_COMPONENT_SIZE) {
      comp_size++;
    }
  }

#if ENABLE_NDN_LOG_DEBUG
  m_measure_tp1 = ndn_time_now_us();
#endif

  ndn_aes_key_t* aes_key = ndn_ac_get_key_for_service(topic->service);
  uint32_t used_size = 0;
  memset(pkt_encoding_buf, 0, sizeof(pkt_encoding_buf));
  ret = ndn_parse_encrypted_payload(data->content_value, data->content_size,
                                    pkt_encoding_buf, &used_size, aes_key->key_id);

#if ENABLE_NDN_LOG_DEBUG
  m_measure_tp2 = ndn_time_now_us();
  NDN_LOG_DEBUG("[PUB/SUB] SUB-NEW-DATA-AES-DEC: %" PRI_ndn_time_us_t "\n", m_measure_tp2 - m_measure_tp1);
#endif

  if (ret != NDN_SUCCESS) {
    NDN_LOG_ERROR("[PUB/SUB] Cannot decrypt the newly published content. Abort...\n");
    if (ret > NDN_OVERSIZE) {
      // bigger than largest error code infers the keyid mismatch
      ndn_ac_trigger_expiration(topic->service, aes_key->key_id + ret);
    }
    return;
  }

#if ENABLE_NDN_LOG_DEBUG
  m_measure_tp1 = ndn_time_now_us();
#endif

  bool pass_schema_check = false;
  if (topic->is_cmd) {
    ndn_rule_storage_t* rules = ndn_rule_storage_get_instance();
    for (int i = 0; i < NDN_TRUST_SCHEMA_MAX_SUBPATTERN_MATCHES; i++) {
      if (rules->rule_names[i].name[0] != '\0') {
        ret = ndn_trust_schema_verify_data_name_key_name_pair(&rules->rule_objects[i],
                                                              &data->name, &data->signature.key_locator_name);
        if (ret == NDN_SUCCESS) {
          pass_schema_check = true;
          break;
        }
      }
    }
  }
  else {
    ndn_trust_schema_rule_t schema;
    ret = ndn_trust_schema_rule_from_strings(&schema, content_same_producer_rule_data_name, strlen(content_same_producer_rule_data_name),
                                             content_same_producer_rule_key_name, strlen(content_same_producer_rule_key_name));
    if (ret == NDN_SUCCESS) {
      pass_schema_check = true;
    }
  }
  if (!pass_schema_check) {
    NDN_LOG_ERROR("[PUB/SUB] Cannot load trust schema rules. Drop.\n");
    return;
  }

#if ENABLE_NDN_LOG_DEBUG
  m_measure_tp2 = ndn_time_now_us();
  NDN_LOG_DEBUG("[PUB/SUB] SUB-NEW-DATA-SCHEMA-VERIFY: %" PRI_ndn_time_us_t "\n", m_measure_tp2 - m_measure_tp1);
#endif

  if (ret != NDN_SUCCESS) {
    NDN_LOG_ERROR("[PUB/SUB] Cannot verify incoming content against trust schemas. Error code: %d\n", ret);
    return;
  }
  NDN_LOG_DEBUG("[PUB/SUB] NEW-DATA-FINSIH-VERIFICATION-TP: %" PRI_ndn_time_us_t " ms\n", ndn_time_now_ms());
  // command FORMAT: /home/service/CMD/identifier[0,2]/command
  // data FORMAT: /home/service/DATA/identifier[0,2]/data-identifier

  ps_event_context_t context = {
    .service = topic->service,
  };
  int scope_len = 0;
  context.scope[scope_len] = '/';
  scope_len++;
  for (int i = 0; i < NDN_PUBSUB_IDENTIFIER_SIZE; i++) {
    if (topic->identifier[i].size != NDN_FWD_INVALID_NAME_COMPONENT_SIZE) {
      memcpy(&context.scope[scope_len], topic->identifier[i].value, topic->identifier[i].size);
      scope_len += topic->identifier[i].size;
      context.scope[scope_len] = '/';
      scope_len++;
    }
  }
  context.scope[scope_len - 1] = '\0';

  ps_event_t event = {
    .data_id = data->name.components[data->name.components_size - 2].value,
    .data_id_len = data->name.components[data->name.components_size - 2].size,
    .payload = pkt_encoding_buf,
    .payload_len = used_size
  };
  topic->callback(&context, &event, topic->userdata);
}

void
_on_new_content_verify_failure(ndn_data_t* data, void* userdata)
{
  (void) userdata;
  NDN_LOG_INFO("[PUB/SUB] New published content cannot pass signature verification. Drop...");
  NDN_LOG_INFO_NAME(&data->name);
}

/** OnData callback function to handle incoming content.
 */
void
_on_new_content(const uint8_t* raw_data, uint32_t data_size, void* userdata)
{
  sub_topic_t* topic = (sub_topic_t*)userdata;
  // check if received before
  ndn_sha256(raw_data, data_size, pkt_encoding_buf);
  if (topic->received_content && memcmp(pkt_encoding_buf, topic->last_digest, 16) == 0) {
    NDN_LOG_INFO("[PUB/SUB] Received duplicate published content/command. Drop");
    return;
  }
  NDN_LOG_INFO("[PUB/SUB] Received new published content/command");
  NDN_LOG_DEBUG("[PUB/SUB] NEW-DATA-ARRIVE-TP: %" PRI_ndn_time_us_t " ms\n", ndn_time_now_ms());
  NDN_LOG_DEBUG("[PUB/SUB] SUB-NEW-DATA-PKT-SIZE: %u Bytes\n", data_size);
  topic->received_content = true;
  memcpy(topic->last_digest, pkt_encoding_buf, 16);

  // parse Data name
  ndn_sig_verifier_verify_data(raw_data, data_size,
                               _on_new_content_verify_success, userdata,
                               _on_new_content_verify_failure, userdata);
}

/** Helper function to construct a name for the Interest to fetch subscribted topic content
 */
void
_construct_sub_interest(ndn_name_t* name, sub_topic_t* topic)
{
  ndn_name_init(name);
  // FORMAT: /home-prefix/service/type/identifier[0,2]
  // home prefix
  ndn_key_storage_t* storage = ndn_key_storage_get_instance();
  /* given that all self_identity have the same home prefix, this is fine */
  ndn_name_append_component(name, &storage->self_identity[0].components[0]);
  ndn_name_append_bytes_component(name, &topic->service, sizeof(topic->service));
  if (topic->is_cmd) {
    ndn_name_append_string_component(name, "CMD", strlen("CMD"));
  }
  else {
    ndn_name_append_string_component(name, "DATA", strlen("DATA"));
  }
  for (int i = 0; i < 2; i++) {
    if (topic->identifier[i].size != NDN_FWD_INVALID_NAME_COMPONENT_SIZE) {
      ndn_name_append_component(name, &topic->identifier[i]);
    }
  }
}

/*
 * Helper function to periodically fetch from the Subsribed Topic.
 */
void
_periodic_sub_content_fetching(void *self, size_t param_length, void *param)
{
  (void)self;
  (void)param_length;
  (void)param;
  ndn_time_ms_t now = ndn_time_now_ms();
  if (now < m_pub_sub_state.m_next_send) {
    ndn_msgqueue_post(NULL, _periodic_sub_content_fetching, 0, NULL);
    return;
  }
  m_pub_sub_state.m_next_send = now + m_pub_sub_state.min_interval;
  sub_topic_t* topic = NULL;
  ndn_name_t name;

  // check the table
  for (int i = 0; i < 5; i++) {
    topic = &m_pub_sub_state.sub_topics[i];
    if (topic->service != NDN_SD_NONE && topic->is_cmd == false && now >= topic->next_interest) {
      // send out subscription interest
      _construct_sub_interest(&name, topic);
      size_t used_size = 0;
      tlv_make_interest(pkt_encoding_buf, sizeof(pkt_encoding_buf), &used_size, 3,
                        TLV_INTARG_NAME_PTR, &name,
                        TLV_INTARG_CANBEPREFIX_BOOL, true,
                        TLV_INTARG_MUSTBEFRESH_BOOL, true);
      m_is_my_own_int = true;
      int ret = ndn_forwarder_express_interest(pkt_encoding_buf, used_size, _on_new_content, _on_sub_timeout, topic);
      m_is_my_own_int = false;
      if (ret != NDN_SUCCESS) {
        NDN_LOG_ERROR("[PUB/SUB] Failed to sent subscription Interest. Error code: %d", ret);
      }
      else {
        NDN_LOG_INFO("[PUB/SUB] Sent subscription Interest");
        NDN_LOG_INFO_NAME(&name);
        // update next_interest time
        topic->next_interest = now + topic->interval;
      }
    }
  }
  // register the event to the message queue again with the smallest time period
  ndn_msgqueue_post(NULL, _periodic_sub_content_fetching, 0, NULL);
}

int
_on_subscription_interest(const uint8_t* raw_interest, uint32_t interest_size, void* userdata)
{
  if (m_is_my_own_int) {
    return NDN_FWD_STRATEGY_MULTICAST;
  }
  // parse interest
  NDN_LOG_INFO("[PUB/SUB] Received Subscription Interest");
  ndn_interest_t interest;
  ndn_interest_from_block(&interest, raw_interest, interest_size);
  NDN_LOG_INFO_NAME(&interest.name);

  // match topic
  pub_topic_t* topic = (pub_topic_t*)userdata;

  // reply the latest content
  int ret = ndn_forwarder_put_data(topic->cache, topic->cache_size);
  if (ret != NDN_SUCCESS) {
    NDN_LOG_ERROR("[PUB/SUB] Cannot reply cached Data. Error code: %d", ret);
    return NDN_FWD_STRATEGY_SUPPRESS;
  }
  NDN_LOG_INFO("[PUB/SUB] Replid cached Data");
  return NDN_FWD_STRATEGY_SUPPRESS;
}

int
_on_notification_interest(const uint8_t* raw_interest, uint32_t interest_size, void* userdata)
{
  if (m_is_my_own_int) {
    return NDN_FWD_STRATEGY_MULTICAST;
  }
  // FORMAT: /home/service/NOTIFY/CMD/identifier[0,2]/action
  NDN_LOG_INFO("[PUB/SUB] On notification Interest");
  ndn_interest_t interest;
  ndn_interest_from_block(&interest, raw_interest, interest_size);
  NDN_LOG_INFO_NAME(&interest.name);

  // check whether identifiers match
  sub_topic_t* topic = (sub_topic_t*)userdata;
  if (topic->identifier[0].size != NDN_FWD_INVALID_NAME_COMPONENT_SIZE
      && name_component_compare(&topic->identifier[0], &interest.name.components[4]) != NDN_SUCCESS) {
    // does not match
    return NDN_FWD_STRATEGY_SUPPRESS;
  }
  if (topic->identifier[1].size != NDN_FWD_INVALID_NAME_COMPONENT_SIZE
      && name_component_compare(&topic->identifier[1], &interest.name.components[5]) != NDN_SUCCESS) {
    // does not match
    return NDN_FWD_STRATEGY_SUPPRESS;
  }

  // send out
  ndn_name_t name;
  ndn_name_init(&name);
  for (int i = 0; i < interest.name.components_size; i++) {
    if (i == 2) {
      continue;
    }
    ndn_name_append_component(&name, &interest.name.components[i]);
  }
  size_t used_size = 0;
  int ret = tlv_make_interest(pkt_encoding_buf, sizeof(pkt_encoding_buf), &used_size, 3,
                              TLV_INTARG_NAME_PTR, &name,
                              TLV_INTARG_CANBEPREFIX_BOOL, true,
                              TLV_INTARG_MUSTBEFRESH_BOOL, true);
  m_is_my_own_int = true;
  if (ret != NDN_SUCCESS) {
    NDN_LOG_ERROR("[PUB/SUB] Failed to construct subscription Interest. Error code: %d", ret);
  }
  ret = ndn_forwarder_express_interest(pkt_encoding_buf, used_size, _on_new_content, _on_sub_timeout, topic);
  m_is_my_own_int = false;
  if (ret != NDN_SUCCESS) {
    NDN_LOG_ERROR("[PUB/SUB] Failed to sent subscription Interest. Error code: %d", ret);
  }
  else {
    NDN_LOG_INFO("[PUB/SUB] Sent subscription Interest");
    NDN_LOG_INFO_NAME(&name);
  }
  return NDN_FWD_STRATEGY_SUPPRESS;
}

void
_subscribe_to(uint8_t service, bool is_cmd, const char* scope,
              uint32_t interval, ps_on_published callback, void* userdata)
{
  if (!m_has_initialized)
    _ps_topics_init();

  // find whether the topic has been subscribed already
  sub_topic_t* topic = _match_sub_topic(service, is_cmd);
  if (!topic) {
    for (int i = 0; i < 5; i++) {
      if (m_pub_sub_state.sub_topics[i].service == NDN_SD_NONE) {
        topic = &m_pub_sub_state.sub_topics[i];
      }
    }
    if (topic == NULL) {
      NDN_LOG_ERROR("[PUB/SUB] No more space for new subscription topics. Abort");
      return;
    }
    topic->service = service;
    topic->is_cmd = is_cmd;
  }

  // update locator
  ndn_name_t locator;
  ndn_name_init(&locator);
  if (strlen(scope) > 0) {
    ndn_name_from_string(&locator, scope, strlen(scope));
  }
  for (int i = 0; i < 2; i++) {
    if (i < locator.components_size) {
      memcpy(&topic->identifier[i], &locator.components[i], sizeof(name_component_t));
    }
    else {
      topic->identifier[i].size = NDN_FWD_INVALID_NAME_COMPONENT_SIZE;
    }
  }
  // update interval, callback, and other state
  if (!is_cmd) {
    topic->interval = interval;
    if (topic->interval < m_pub_sub_state.min_interval) {
      m_pub_sub_state.min_interval = topic->interval;
    }
    topic->next_interest = ndn_time_now_ms() + topic->interval;
  }
  else {
    topic->interval = 0;
  }
  topic->callback = callback;
  topic->userdata = userdata;

  // if subscribe to a command topic, register the interest filter to listen to NOTIF for immediate cmd fetch
  // FORMAT: /home-prefix/service/NOTIFY/CMD/identifier[0,2]
  if (is_cmd) {
    ndn_name_t name;
    ndn_name_init(&name);
    ndn_key_storage_t* storage = ndn_key_storage_get_instance();
    ndn_name_append_component(&name, &storage->self_identity[0].components[0]);
    ndn_name_append_bytes_component(&name, &topic->service, sizeof(topic->service));
    ndn_name_append_string_component(&name, "NOTIFY", strlen("NOTIFY"));
    ndn_forwarder_register_name_prefix(&name, _on_notification_interest, topic);
  }
}

void
ps_subscribe_to_content(uint8_t service, const char* scope,
                        uint32_t interval, ps_on_content_published callback, void* userdata)
{
  return _subscribe_to(service, false, scope, interval, callback, userdata);
}

void
ps_subscribe_to_command(uint8_t service, const char* scope, ps_on_command_published callback, void* userdata)
{
  return _subscribe_to(service, true, scope, 0, callback, userdata);
}

void
ps_after_bootstrapping()
{
  if (!m_has_initialized)
    _ps_topics_init();
  _periodic_sub_content_fetching(NULL, 0, NULL);
}

void
ps_publish_content(uint8_t service, const ps_event_t* event)
{
  if (!m_has_initialized)
    _ps_topics_init();

  int ret = 0;
  // Prefix FORMAT: /home/service/DATA
  ndn_name_t name;
  ndn_name_init(&name);
  ndn_key_storage_t* storage = ndn_key_storage_get_instance();
  ndn_name_append_component(&name, &storage->self_identity[0].components[0]);
  ndn_name_append_bytes_component(&name, &service, sizeof(service));
  ndn_name_append_string_component(&name, "DATA", strlen("DATA"));

  // published on this topic before? update the cache
  pub_topic_t* topic = NULL;
  topic = _match_pub_topic(service, false);
  if (!topic) {
    for (int i = 0; i < 5; i++) {
      if (m_pub_sub_state.pub_topics[i].service == NDN_SD_NONE) {
        topic = &m_pub_sub_state.pub_topics[i];
        break;
      }
    }
    if (topic == NULL) {
      NDN_LOG_INFO("[PUB/SUB] No availble topic, will drop the oldest pub topic.");
      uint64_t min_last_tp = m_pub_sub_state.pub_topics[0].last_update_tp;
      int index = 0;
      for (int i = 1; i < 5; i++) {
        if (m_pub_sub_state.pub_topics[i].last_update_tp < min_last_tp) {
          min_last_tp = m_pub_sub_state.pub_topics[i].last_update_tp;
          index = i;
        }
      }
      topic = &m_pub_sub_state.pub_topics[index];
      // TODO: unregister the prefix registered by the old topic
    }
    // register the new prefix
    ret = ndn_forwarder_register_name_prefix(&name, _on_subscription_interest, topic);
    if (ret != NDN_SUCCESS) {
      NDN_LOG_ERROR("[PUB/SUB] Cannot register prefix for newly published content. Error Code: %d", ret);
    }
    topic->service = service;
    topic->is_cmd = false;
  }
  topic->last_update_tp = ndn_time_now_ms();
  // Append the last several component to the Data name
  // Data name FORMAT: /home/service/DATA/room/device-id/content-id/tp
  /* given that all self_identity have same <room> and <device-id>, this is fine */
  ndn_name_append_component(&name, &storage->self_identity[0].components[storage->self_identity[0].components_size - 2]);
  ndn_name_append_component(&name, &storage->self_identity[0].components[storage->self_identity[0].components_size - 1]);
  ndn_name_append_bytes_component(&name, event->data_id, event->data_id_len);
  name_component_t tp_comp;
  name_component_from_timestamp(&tp_comp, topic->last_update_tp);
  ndn_name_append_component(&name, &tp_comp);

#if ENABLE_NDN_LOG_DEBUG
  m_measure_tp1 = ndn_time_now_us();
#endif

  // Encrypt payload
  uint32_t used_size = 0;
  ndn_aes_key_t* service_aes_key = ndn_ac_get_key_for_service(topic->service);
  ret = ndn_gen_encrypted_payload(event->payload, event->payload_len, pkt_encoding_buf, &used_size,
                                  service_aes_key->key_id, NULL, 0);

#if ENABLE_NDN_LOG_DEBUG
  m_measure_tp2 = ndn_time_now_us();
  NDN_LOG_DEBUG("[PUB/SUB] PUB-CONTENT-DATA-AES-ENC: %" PRI_ndn_time_us_t "\n", m_measure_tp2 - m_measure_tp1);
#endif


  if (ret != NDN_SUCCESS) {
    NDN_LOG_ERROR("[PUB/SUB] Cannot encrypt content to publish. Error code: %d", ret);
    return;
  }

  memset(topic->cache, 0, sizeof(topic->cache));
  uint32_t default_freshness_period = 0;
  if (!event->freshness_period) {
    // this user does not define the freshness period, it will pick 8000ms as default
    default_freshness_period = 8000;
  }
  else {
    default_freshness_period = event->freshness_period;
  }
  // select identity key
  ndn_name_t* signing_identity = ndn_key_storage_get_self_identity(service);
  ndn_ecc_prv_t* signing_identity_key = ndn_key_storage_get_self_identity_key(service);
  if (signing_identity == NULL || signing_identity_key == NULL) {
    NDN_LOG_ERROR("[PUB/SUB] Cannot find proper identity to sign");
    return;
  }
  ret = tlv_make_data(topic->cache, sizeof(topic->cache), (size_t *) &topic->cache_size, 7,
                      TLV_DATAARG_NAME_PTR, &name,
                      TLV_DATAARG_CONTENT_BUF, pkt_encoding_buf,
                      TLV_DATAARG_CONTENT_SIZE, used_size,
                      TLV_DATAARG_FRESHNESSPERIOD_U64, (uint64_t)default_freshness_period,
                      TLV_DATAARG_SIGTYPE_U8, NDN_SIG_TYPE_ECDSA_SHA256,
                      TLV_DATAARG_IDENTITYNAME_PTR, signing_identity,
                      TLV_DATAARG_SIGKEY_PTR, signing_identity_key);
  if (ret != NDN_SUCCESS) {
    NDN_LOG_ERROR("[PUB/SUB] Content Data cannot be generated. Error code: %d", ret);
    return;
  }
  NDN_LOG_DEBUG("[PUB/SUB] PUB-CONTENT-PKT-SIZE: %u Bytes\n", topic->cache_size);
  NDN_LOG_INFO("[PUB/SUB] Content Data has been generated");
  NDN_LOG_INFO_NAME(&name);
}

void
ps_publish_command(uint8_t service, const char* scope, const ps_event_t* event)
{
  if (!m_has_initialized)
    _ps_topics_init();

  int ret = 0;
  // Prefix FORMAT: /home/service/CMD
  ndn_name_t name;
  ndn_name_init(&name);
  ndn_key_storage_t* storage = ndn_key_storage_get_instance();
  ndn_name_append_component(&name, &storage->self_identity[0].components[0]);
  ndn_name_append_bytes_component(&name, &service, sizeof(service));
  ndn_name_append_string_component(&name, "CMD", strlen("CMD"));

  // published on this topic before? update the cache
  pub_topic_t* topic = NULL;
  topic = _match_pub_topic(service, true);
  if (!topic) {
    for (int i = 0; i < 5; i++) {
      if (m_pub_sub_state.pub_topics[i].service == NDN_SD_NONE) {
        topic = &m_pub_sub_state.pub_topics[i];
      }
    }
    if (topic == NULL) {
      NDN_LOG_INFO("[PUB/SUB] No availble topic, will drop the oldest pub topic.");
      uint64_t min_last_tp = m_pub_sub_state.pub_topics[0].last_update_tp;
      int index = -1;
      for (int i = 1; i < 5; i++) {
        if (m_pub_sub_state.pub_topics[i].last_update_tp < min_last_tp) {
          min_last_tp = m_pub_sub_state.pub_topics[i].last_update_tp;
          index = i;
        }
      }
      topic = &m_pub_sub_state.pub_topics[index];
      // TODO: unregister the prefix registered by the old topic
    }
    // register the new prefix
    ret = ndn_forwarder_register_name_prefix(&name, _on_subscription_interest, topic);
    if (ret != NDN_SUCCESS) {
      NDN_LOG_ERROR("[PUB/SUB] Cannot register prefix for newly published command. Error Code: %d", ret);
    }
    topic->service = service;
    topic->is_cmd = true;
  }
  topic->last_update_tp = ndn_time_now_ms();
  memset(topic->cache, 0, sizeof(topic->cache));

  // Append the last several component to the Data name
  // Data name FORMAT: /home/service/CMD/identifier[0,2]/command-id
  ndn_name_t scope_name;
  if (strlen(scope) > 0) {
    ndn_name_from_string(&scope_name, scope, strlen(scope));
    for (int i = 0; i < scope_name.components_size; i++) {
      ndn_name_append_component(&name, &scope_name.components[i]);
    }
  }
  ndn_name_append_bytes_component(&name, event->data_id, event->data_id_len);
  // TODO: currently I appended timestamp. Further discussion is needed.
  ndn_time_ms_t tp = ndn_time_now_ms();
  name_component_t tp_comp;
  name_component_from_timestamp(&tp_comp, tp);
  ndn_name_append_component(&name, &tp_comp);

#if ENABLE_NDN_LOG_DEBUG
  m_measure_tp1 = ndn_time_now_us();
#endif

  // Encrypt payload
  uint32_t used_size = 0;
  ndn_aes_key_t* service_aes_key = ndn_ac_get_key_for_service(topic->service);
  ret = ndn_gen_encrypted_payload(event->payload, event->payload_len, pkt_encoding_buf, &used_size,
                                  service_aes_key->key_id, NULL, 0);
  if (ret != NDN_SUCCESS) {
    NDN_LOG_ERROR("[PUB/SUB] Cannot encrypt command payload to publish. Error code: %d", ret);
    return;
  }

#if ENABLE_NDN_LOG_DEBUG
  m_measure_tp2 = ndn_time_now_us();
  NDN_LOG_DEBUG("[PUB/SUB] PUB-COMMAND-DATA-AES-ENC: %" PRI_ndn_time_us_t "\n", m_measure_tp2 - m_measure_tp1);
#endif

  uint32_t default_freshness_period = 0;
  if (!event->freshness_period) {
    // this user does not define the freshness period, it will pick 8000ms as default
    default_freshness_period = 8000;
  }
  else {
    default_freshness_period = event->freshness_period;
  }
  // select identity key
  ndn_name_t* signing_identity = ndn_key_storage_get_self_identity(service);
  ndn_ecc_prv_t* signing_identity_key = ndn_key_storage_get_self_identity_key(service);
  if (signing_identity == NULL || signing_identity_key == NULL) {
    NDN_LOG_ERROR("[PUB/SUB] Cannot find proper identity to sign");
    return;
  }
  ret = tlv_make_data(topic->cache, sizeof(topic->cache), (size_t *) &topic->cache_size, 7,
                      TLV_DATAARG_NAME_PTR, &name,
                      TLV_DATAARG_CONTENT_BUF, pkt_encoding_buf,
                      TLV_DATAARG_CONTENT_SIZE, used_size,
                      TLV_DATAARG_FRESHNESSPERIOD_U64, (uint64_t)default_freshness_period,
                      TLV_DATAARG_SIGTYPE_U8, NDN_SIG_TYPE_ECDSA_SHA256,
                      TLV_DATAARG_IDENTITYNAME_PTR, signing_identity,
                      TLV_DATAARG_SIGKEY_PTR, signing_identity_key);
  NDN_LOG_DEBUG("[PUB/SUB] PUB-CMD-PKT-SIZE: %u Bytes\n", topic->cache_size);
  NDN_LOG_INFO("[PUB/SUB] CMD Data has been generated");
  NDN_LOG_INFO_NAME(&name);

  // express the /Notify Interest
  // FORMAT: /home/service/NOTIFY/CMD/identifier[0,2]/action
  ndn_name_init(&name);
  ndn_name_append_component(&name, &storage->self_identity[0].components[0]);
  ndn_name_append_bytes_component(&name, &service, sizeof(service));
  ndn_name_append_string_component(&name, "NOTIFY", strlen("NOTIFY"));
  ndn_name_append_string_component(&name, "CMD", strlen("CMD"));
  if (strlen(scope) > 0) {
    for (int i = 0; i < scope_name.components_size; i++) {
      ndn_name_append_component(&name, &scope_name.components[i]);
    }
  }
  ndn_name_append_bytes_component(&name, event->data_id, event->data_id_len);
  ndn_name_append_component(&name, &tp_comp);

  // send out the notification Interest
  uint32_t buffer_length = 0;
  tlv_make_interest(pkt_encoding_buf, sizeof(pkt_encoding_buf), (size_t *) &buffer_length, 3,
                    TLV_INTARG_NAME_PTR, &name,
                    TLV_INTARG_CANBEPREFIX_BOOL, true,
                    TLV_INTARG_MUSTBEFRESH_BOOL, true);
  m_is_my_own_int = true;
  ret = ndn_forwarder_express_interest(pkt_encoding_buf, buffer_length, _on_new_content, _on_sub_timeout, NULL);
  m_is_my_own_int = false;
  NDN_LOG_INFO("[PUB/SUB] Sent notification Interest for the newly generated cmd");
  NDN_LOG_INFO_NAME(&name);
}
