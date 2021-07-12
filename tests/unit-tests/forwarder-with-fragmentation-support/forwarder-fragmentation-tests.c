/*
 * Copyright (C) 2020 Hanwen Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <errno.h>
#include "../CUnit/CUnit.h"

#include "../test-helpers.h"
#include "../print-helpers.h"
#include "../forwarder/forwarder-tests-def.h"

#include "ndn-lite/ndn-constants.h"
#include "ndn-lite/encode/interest.h"
#include "ndn-lite/encode/data.h"
#include "ndn-lite/forwarder/forwarder.h"
#include "dummy-face-with-mtu.h"

// five seconds
#define FORWARDER_TEST_WAIT_TIME_U_SEC 5000000
// how many microseconds are in a second
#define MICROSECONDS_PER_SECOND 1000000

const char *_current_test_name;
static bool _current_forwarder_test_app_received_interest = false;
// static bool _current_forwarder_test_app_received_data = false;
// static bool _current_forwarder_test_all_calls_succeeded = false;

int ff_test_sign_data(const char* id, uint32_t id_len, ndn_encoder_t* encoder, ndn_data_t* data);

void ff_on_interest_timeout_callback(void *userdata)
{
  (void)userdata;
  printf("On Time Out\n");
}

int ff_on_interest(const uint8_t *interest, uint32_t interest_size, void *userdata)
{
  (void)interest;
  (void)interest_size;
  (void)userdata;
  //printf("application receives an Interest\n");
  _current_forwarder_test_app_received_interest = true;
  return 0;
}

static bool ff_forwarder_put_data_received = false;

void ff_on_data_callback(const uint8_t *data, uint32_t data_size, void *userdata)
{
  (void) userdata;
  ndn_data_t data_check;
  ndn_ecc_pub_t pub_key;
  int result = ndn_ecc_pub_init(&pub_key, test_ecc_secp256r1_public_raw_1, sizeof(test_ecc_secp256r1_public_raw_1),
                                NDN_ECDSA_CURVE_SECP256R1, 1234);
  CU_ASSERT_EQUAL(result, 0);
  result = ndn_data_tlv_decode_ecdsa_verify(&data_check, data, data_size, &pub_key);
  CU_ASSERT_EQUAL(result, 0);
  ff_forwarder_put_data_received = true;
}

/*
   *  +----+       +---------+  -- FRAGMENTATION -->   +------------+
   *  |app /ndn -- |forwarder|                         /aaa dummyface|
   *  +----+       +---------+    <-- ASSEMBLY --      +------------+
   *
   *        -----I: /test2/name1 --->
   *        <----D: /test2/name1 ---- (OVERSIZED)
   */
void ff_forwarder_with_fragmentation_test()
{
  ndn_forwarder_init();
  
  // prepare dummy face (MTU=100)
  ndn_dummy_face_with_mtu_t *dummy_face;
  dummy_face = ndn_dummy_face_construct();
  
  // add route
  int ret_val = ndn_forwarder_add_route_by_str(&dummy_face->intf, "/test2", strlen("/test2"));
  CU_ASSERT_EQUAL(ret_val, 0);
  
  // create interest
  ndn_interest_t interest;
  ndn_interest_init(&interest);
  char name_string[] = "/test2/name1";
  ret_val = ndn_name_from_string(&interest.name, name_string, sizeof(name_string));
  CU_ASSERT_EQUAL(ret_val, 0);
  uint8_t interest_block[256] = {0};
  ndn_encoder_t encoder;
  encoder_init(&encoder, interest_block, 256);
  ret_val = ndn_interest_tlv_encode(&encoder, &interest);
  CU_ASSERT_EQUAL(ret_val, 0);
  
  // express interest
  ret_val = ndn_forwarder_express_interest(interest_block,
                                           encoder.offset,
                                           ff_on_data_callback,
                                           ff_on_interest_timeout_callback,
                                           NULL);
  CU_ASSERT_EQUAL(ret_val, 0);

  // prepare data content
  uint8_t buf[10] = {0, 1, 3, -6, 3, -10, 18, 42, 189, 32};
  uint8_t block_value[1024];
  ndn_data_t data;
  ret_val = ndn_data_set_content(&data, buf, sizeof(buf));
  CU_ASSERT_EQUAL(ret_val, 0);

  // set data name, metainfo
  char data_name_string[] = "/test2/name1";
  ret_val = ndn_name_from_string(&data.name, data_name_string, sizeof(data_name_string));
  CU_ASSERT_EQUAL(ret_val, 0);
  ndn_metainfo_init(&data.metainfo);
  ndn_metainfo_set_content_type(&data.metainfo, NDN_CONTENT_TYPE_BLOB);

  // sign data
  encoder_init(&encoder, block_value, 1024);
  ret_val = ff_test_sign_data("ndn/zhiyi", strlen("ndn/zhiyi"), &encoder, &data);
  CU_ASSERT_EQUAL(ret_val, 0);

  // put data to forwarder
  ret_val = ndn_dummy_face_send_with_fragmenter(&dummy_face->intf, block_value, encoder.offset);
  // ret_val = ndn_forwarder_receive(&dummy_face->intf, block_value, encoder.offset);
  recv_from_face(dummy_face);
  CU_ASSERT_EQUAL(ret_val, 0);

  while (!ff_forwarder_put_data_received){}
  CU_ASSERT_TRUE(ff_forwarder_put_data_received);
}

int ff_test_sign_data(const char* id, uint32_t id_len, ndn_encoder_t* encoder, ndn_data_t* data) {
  ndn_ecc_prv_t prv_key;
  ndn_ecc_prv_init(&prv_key, test_ecc_secp256r1_private_raw_1, sizeof(test_ecc_secp256r1_private_raw_1), NDN_ECDSA_CURVE_SECP256R1, 1234);
  ndn_name_t identity;
  int ret_val = ndn_name_from_string(&identity, id, id_len);
  CU_ASSERT_EQUAL(ret_val, 0);
  ret_val = ndn_data_tlv_encode_ecdsa_sign(encoder, data, &identity, &prv_key);
  CU_ASSERT_EQUAL(ret_val, 0);
  return 0;
}

void add_forwarder_fragmentation_test_suite()
{
  CU_pSuite pSuite = NULL;

  /* add a suite to the registry */
  pSuite = CU_add_suite("Forwarder with Fragmentation Support Test", NULL, NULL);
  if (NULL == pSuite)
  {
    CU_cleanup_registry();
    // return CU_get_error();
    return;
  }
  if (
      NULL == CU_add_test(pSuite, "forwarder_with_fragmentation_test", ff_forwarder_with_fragmentation_test))
  {
    CU_cleanup_registry();
    // return CU_get_error();
    return;
  }
}