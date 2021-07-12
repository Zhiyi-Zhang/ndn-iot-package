/*
 * Copyright (C) 2018 Zhiyi Zhang, Tianyuan Yu, Edward Lu, Hanwen Zhang
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */
#include "forwarder-tests.h"

#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <errno.h>
#include "../CUnit/CUnit.h"

#include "forwarder-tests-def.h"
#include "../test-helpers.h"
#include "../print-helpers.h"

#include "ndn-lite/ndn-constants.h"
#include "ndn-lite/encode/interest.h"
#include "ndn-lite/encode/data.h"
#include "ndn-lite/forwarder/fib.h"
#include "ndn-lite/forwarder/forwarder.h"
#include "ndn-lite/face/dummy-face.h"

// five seconds
#define FORWARDER_TEST_WAIT_TIME_U_SEC 5000000
// how many microseconds are in a second
#define MICROSECONDS_PER_SECOND 1000000

forwarder_test_t *_current_forwarder_test = NULL;
static uint8_t _forwarder_test_raw_pub_key_arr[NDN_SEC_ECC_MAX_PUBLIC_KEY_SIZE];
static uint32_t _forwarder_test_raw_pub_key_arr_len = 0;

const char *_current_test_name;
static bool _current_forwarder_test_app_received_interest = false;
static bool _current_forwarder_test_app_received_data = false;
static bool _current_forwarder_test_all_calls_succeeded = false;

static struct timeval _current_forwarder_test_start_time;
static struct timeval _current_time;
static uint32_t _current_forwarder_test_start_time_u_secs;
static uint32_t _current_time_u_secs;

int test_sign_data(const char* id, uint32_t id_len, ndn_encoder_t* encoder, ndn_data_t* data);

void on_data_callback(const uint8_t *data, uint32_t data_size, void *userdata)
{
  (void) userdata;
  //printf("application receives a Data\n");
  ndn_data_t data_check;
  ndn_ecc_pub_t pub_key;
  int result = ndn_ecc_pub_init(&pub_key, _forwarder_test_raw_pub_key_arr, _forwarder_test_raw_pub_key_arr_len,
                                NDN_ECDSA_CURVE_SECP256R1, 1234);
  CU_ASSERT_EQUAL(result, 0);
  if (result != 0)
  {
    print_error(_current_test_name, "on_data_callback", "ndn_ecc_pub_init", result);
    _current_forwarder_test_all_calls_succeeded = false;
  }

  /* printf("Value of data in on_data_callback:\n"); */
  /* for (uint32_t i = 0; i < data_size; i++) { */
  /*   if (i > 0) printf(":"); */
  /*   printf("%02X", data[i]); */
  /* } */
  /* printf("\n"); */

  result = ndn_data_tlv_decode_ecdsa_verify(&data_check, data, data_size, &pub_key);
  CU_ASSERT_EQUAL(result, 0);
  if (result == 0)
  {
    _current_forwarder_test_app_received_data = true;
    _current_forwarder_test = NULL;
  }
  else
  {
    print_error(_current_test_name, "on_data_callback", "ndn_data_tlv_decode_ecdsa_verify", result);
    _current_forwarder_test_app_received_data = false;
    _current_forwarder_test = NULL;
  }
}

void on_interest_timeout_callback(void *userdata)
{
  (void)userdata;
  printf("On Time Out\n");
}

int on_interest(const uint8_t *interest, uint32_t interest_size, void *userdata)
{
  (void)interest;
  (void)interest_size;
  (void)userdata;
  //printf("application receives an Interest\n");
  _current_forwarder_test_app_received_interest = true;
  return 0;
}

void _run_forwarder_test(forwarder_test_t *test);

bool run_forwarder_tests(void)
{
  memset(forwarder_test_results, 0, sizeof(bool) * FORWARDER_NUM_TESTS);
  printf("\n");
  for (int i = 0; i < FORWARDER_NUM_TESTS; i++)
  {
    _run_forwarder_test(&forwarder_tests[i]);
  }

  // spin until current_forwarder_test is set to NULL, meaning that the last
  // forwarder test has completed
  while (_current_forwarder_test != NULL)
  {
  }

  return check_all_tests_passed(forwarder_test_results, forwarder_test_names,
                                FORWARDER_NUM_TESTS);
}

void _run_forwarder_test(forwarder_test_t *test)
{
  _current_test_name = test->test_names[test->test_name_index];
  int ret_val = -1;
  ndn_security_init();

  _current_forwarder_test_app_received_interest = false;
  _current_forwarder_test_app_received_data = false;
  _current_forwarder_test_all_calls_succeeded = true;

  ret_val = gettimeofday(&_current_forwarder_test_start_time, NULL);
  CU_ASSERT_EQUAL(ret_val, 0);
  if (ret_val != 0)
  {
    _current_forwarder_test_all_calls_succeeded = false;
    print_error(_current_test_name, "_run_forwarder_test", "gettimeofday for forwarder test start time", errno);
  }

  _current_forwarder_test_start_time_u_secs = _current_forwarder_test_start_time.tv_sec * MICROSECONDS_PER_SECOND +
                                              _current_forwarder_test_start_time.tv_usec;

  // The forwarder unit test model
  /*
   *  +----+       +---------+     +------------+
   *  |app /ndn -- |forwarder| -- /aaa dummyface|
   *  +----+       +---------+     +------------+
   *
   *        -----I: /aaa/bbb/ccc/ddd --->
   *        <----I: /ndn/hello ----------
   *        <----D: /aaa/bbb/ccc/ddd ----
   */

  // spin until current_forwarder_test is equal to NULL, which means that
  // either this is the first forwarder test, or any previous forwarder tests
  // finished
  while (_current_forwarder_test != NULL)
  {
  }

  _current_forwarder_test = test;
  memcpy(_forwarder_test_raw_pub_key_arr, test->pub_key_raw_val, test->pub_key_raw_len);
  _forwarder_test_raw_pub_key_arr_len = test->pub_key_raw_len;

  // tests start
  ndn_forwarder_init();

  ndn_dummy_face_t *dummy_face;
  dummy_face = ndn_dummy_face_construct();

  // add FIB entry
  //printf("\n***Add dummy face to FIB with prefix /aaa***\n");
  char prefix_string[] = "/aaa";
  ndn_name_t prefix;
  ret_val = ndn_name_from_string(&prefix, prefix_string, sizeof(prefix_string));
  CU_ASSERT_EQUAL(ret_val, 0);
  if (ret_val != 0)
  {
    _current_forwarder_test_all_calls_succeeded = false;
    print_error(_current_test_name, "_run_forwarder_test", "ndn_name_from_string", ret_val);
  }
  uint8_t tmp_name_buf[256] = {0};
  ndn_encoder_t tmp_name_encoder;
  encoder_init(&tmp_name_encoder, tmp_name_buf, 256);
  ndn_name_tlv_encode(&tmp_name_encoder, &prefix);
  ret_val = ndn_forwarder_add_route(&dummy_face->intf, tmp_name_buf, tmp_name_encoder.offset);
  CU_ASSERT_EQUAL(ret_val, 0);
  if (ret_val != 0)
  {
    _current_forwarder_test_all_calls_succeeded = false;
    print_error(_current_test_name, "_run_forwarder_test", "ndn_forwarder_fib_insert", ret_val);
  }

  // create interest
  ndn_interest_t interest;
  ndn_interest_init(&interest);
  char name_string[] = "/aaa/bbb/ccc/ddd";
  ret_val = ndn_name_from_string(&interest.name, name_string, sizeof(name_string));
  CU_ASSERT_EQUAL(ret_val, 0);
  if (ret_val != 0)
  {
    _current_forwarder_test_all_calls_succeeded = false;
    print_error(_current_test_name, "_run_forwarder_test", "ndn_name_from_string", ret_val);
  }
  uint8_t interest_block[256] = {0};
  ndn_encoder_t encoder;
  encoder_init(&encoder, interest_block, 256);
  ret_val = ndn_interest_tlv_encode(&encoder, &interest);
  CU_ASSERT_EQUAL(ret_val, 0);
  if (ret_val != 0)
  {
    _current_forwarder_test_all_calls_succeeded = false;
    print_error(_current_test_name, "_run_forwarder_test", "ndn_interest_tlv_encode", ret_val);
  }

  // express Interest
  ret_val = ndn_forwarder_express_interest(NULL, 0, NULL, on_interest_timeout_callback, NULL);
  CU_ASSERT_EQUAL(ret_val, NDN_INVALID_POINTER);
  //printf("\n***Express Interest /aaa/bbb/ccc/ddd***\n");
  ret_val = ndn_forwarder_express_interest(
      interest_block,
      encoder.offset,
      on_data_callback,
      on_interest_timeout_callback,
      NULL);
  CU_ASSERT_EQUAL(ret_val, 0);
  if (ret_val != 0)
  {
    _current_forwarder_test_all_calls_succeeded = false;
    print_error(_current_test_name, "_run_forwarder_test", "ndn_direct_face_express_interest", ret_val);
  }

  // register a prefix
  //printf("\n***Register the Interest Prefix /ndn***\n");
  char prefix_string2[] = "/ndn";
  ndn_name_t prefix2;
  ret_val = ndn_name_from_string(&prefix2, prefix_string2, sizeof(prefix_string2));
  CU_ASSERT_EQUAL(ret_val, 0);
  if (ret_val != 0)
  {
    _current_forwarder_test_all_calls_succeeded = false;
    print_error(_current_test_name, "_run_forwarder_test", "ndn_name_from_string", ret_val);
  }
  encoder_init(&tmp_name_encoder, tmp_name_buf, 256);
  ndn_name_tlv_encode(&tmp_name_encoder, &prefix2);
  ret_val = ndn_forwarder_register_prefix(tmp_name_buf, tmp_name_encoder.offset, on_interest, NULL);
  CU_ASSERT_EQUAL(ret_val, 0);
  if (ret_val != 0)
  {
    _current_forwarder_test_all_calls_succeeded = false;
    print_error(_current_test_name, "_run_forwarder_test", "ndn_direct_face_register_prefix", ret_val);
  }

  // receive an Interest
  char name_string2[] = "/ndn/hello";
  ret_val = ndn_name_from_string(&interest.name, name_string2, sizeof(name_string2));
  CU_ASSERT_EQUAL(ret_val, 0);
  if (ret_val != 0)
  {
    _current_forwarder_test_all_calls_succeeded = false;
    print_error(_current_test_name, "_run_forwarder_test", "ndn_name_from_string", ret_val);
  }
  memset(interest_block, 0, 256);
  encoder_init(&encoder, interest_block, 256);
  ret_val = ndn_interest_tlv_encode(&encoder, &interest);
  CU_ASSERT_EQUAL(ret_val, 0);
  if (ret_val != 0)
  {
    _current_forwarder_test_all_calls_succeeded = false;
    print_error(_current_test_name, "_run_forwarder_test", "ndn_interest_tlv_encode", ret_val);
  }
  //printf("\n***Dummy Face receives an Interest /aaa/bbb/ccc/ddd***\n");
  ret_val = ndn_forwarder_receive(&dummy_face->intf, interest_block, encoder.offset);
  CU_ASSERT_EQUAL(ret_val, 0);
  if (ret_val != 0)
  {
    _current_forwarder_test_all_calls_succeeded = false;
    print_error(_current_test_name, "_run_forwarder_test", "ndn_forwarder_receive", ret_val);
  }

  // prepare Data content and Data packet
  uint8_t buf[10] = {2, 2, 2, 2, 2, 2, 2, 2, 2, 2};
  uint8_t block_value[1024];
  ndn_data_t data;
  ret_val = ndn_data_set_content(&data, buf, sizeof(buf));
  CU_ASSERT_EQUAL(ret_val, 0);
  if (ret_val != 0)
  {
    _current_forwarder_test_all_calls_succeeded = false;
    print_error(_current_test_name, "_run_forwarder_test", "ndn_data_set_content", ret_val);
  }

  // set name, metainfo
  char data_name_string[] = "/aaa/bbb/ccc/ddd";
  ret_val = ndn_name_from_string(&data.name, data_name_string, sizeof(data_name_string));
  CU_ASSERT_EQUAL(ret_val, 0);
  if (ret_val != 0)
  {
    _current_forwarder_test_all_calls_succeeded = false;
    print_error(_current_test_name, "_run_forwarder_test", "ndn_name_from_string", ret_val);
  }
  ndn_metainfo_init(&data.metainfo);
  ndn_metainfo_set_content_type(&data.metainfo, NDN_CONTENT_TYPE_BLOB);

  // sign the packet
  encoder_init(&encoder, block_value, 1024);
  ret_val = test_sign_data("ndn/zhiyi", strlen("ndn/zhiyi"), &encoder, &data);
  CU_ASSERT_EQUAL(ret_val, 0);

  // receive the Data packet
  //printf("\n***Dummy Face receives an Data /aaa/bbb/ccc/ddd***\n");
  ret_val = ndn_forwarder_receive(&dummy_face->intf, block_value, encoder.offset);
  // ret_val = ndn_forwarder_put_data(block_value, encoder.offset);
  CU_ASSERT_EQUAL(ret_val, 0);
  if (ret_val != 0)
  {
    _current_forwarder_test_all_calls_succeeded = false;
    print_error(_current_test_name, "_run_forwarder_test", "ndn_forwarder_receive", ret_val);
  }

  // test remove route /aaa
  encoder_init(&tmp_name_encoder, tmp_name_buf, 256);
  ndn_name_tlv_encode(&tmp_name_encoder, &prefix);
  ret_val = ndn_forwarder_remove_route(&dummy_face->intf, tmp_name_buf, tmp_name_encoder.offset);
  CU_ASSERT_EQUAL(ret_val, 0);
  // test remove all route /aaa, expect NDN_FWD_NO_EFFECT
  ret_val = ndn_forwarder_remove_all_routes(tmp_name_buf, tmp_name_encoder.offset);
  CU_ASSERT_EQUAL(ret_val, NDN_FWD_NO_EFFECT);

  // test unregister face
  ret_val = ndn_forwarder_unregister_face(&dummy_face->intf);
  CU_ASSERT_EQUAL(ret_val, 0);

  // test unregister prefix /ndn
  encoder_init(&tmp_name_encoder, tmp_name_buf, 256);
  ndn_name_tlv_encode(&tmp_name_encoder, &prefix2);
  ret_val = ndn_forwarder_unregister_prefix(tmp_name_buf, tmp_name_encoder.offset);
  CU_ASSERT_EQUAL(ret_val, 0);

  // spin until current_forwarder_test is equal to NULL (which means that
  // the current forwarder test has finished) OR until test has passed the
  // time limit of FORWARDER_TEST_WAIT_TIME_U_SEC
  do
  {
    ret_val = gettimeofday(&_current_time, NULL);

    _current_time_u_secs = _current_time.tv_sec * MICROSECONDS_PER_SECOND + _current_time.tv_usec;

    CU_ASSERT_EQUAL(ret_val, 0);
    if (ret_val != 0)
    {
      _current_forwarder_test_all_calls_succeeded = false;
      print_error(_current_test_name, "_run_forwarder_test", "gettimeofday for _current_time", ret_val);
    }
    //printf("Value of _current_time_u_secs: %ud\n", _current_time_u_secs);
    //printf("Value of _current_forwarder_test_start_time_u_secs: %ud\n", _current_forwarder_test_start_time_u_secs);
    //printf("Value of _current_time_u_secs - _current_forwarder_test_start_time_u_secs: %ud\n",
    //        _current_time_u_secs - _current_forwarder_test_start_time_u_secs);
  } while (_current_forwarder_test != NULL &&
           _current_time_u_secs - _current_forwarder_test_start_time_u_secs < FORWARDER_TEST_WAIT_TIME_U_SEC);

  if (_current_forwarder_test_app_received_interest &&
      _current_forwarder_test_app_received_data &&
      _current_forwarder_test_all_calls_succeeded)
  {
    *test->passed = true;
    _current_forwarder_test = NULL;
  }
  else
  {
    *test->passed = false;
    _current_forwarder_test = NULL;
  }
}

static bool forwarder_put_data_received = false;

void on_data_callback2(const uint8_t *data, uint32_t data_size, void *userdata)
{
  (void) userdata;
  ndn_data_t data_check;
  ndn_ecc_pub_t pub_key;
  int result = ndn_ecc_pub_init(&pub_key, _forwarder_test_raw_pub_key_arr, _forwarder_test_raw_pub_key_arr_len,
                                NDN_ECDSA_CURVE_SECP256R1, 1234);
  CU_ASSERT_EQUAL(result, 0);
  result = ndn_data_tlv_decode_ecdsa_verify(&data_check, data, data_size, &pub_key);
  CU_ASSERT_EQUAL(result, 0);
  forwarder_put_data_received = true;
}

/*
   *  +----+       +---------+     +------------+
   *  |app /ndn -- |forwarder| -- /aaa dummyface|
   *  +----+       +---------+     +------------+
   *
   *        -----I: /test2/name1 --->
   *        <----D: /test2/name1 ----
   */
void forwarder_put_data_test()
{
  ndn_forwarder_init();
  
  // prepare dummy face
  ndn_dummy_face_t *dummy_face;
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
                                           on_data_callback2,
                                           on_interest_timeout_callback,
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
  ret_val = test_sign_data("ndn/zhiyi", strlen("ndn/zhiyi"), &encoder, &data);
  CU_ASSERT_EQUAL(ret_val, 0);

  // put data to forwarder
  ret_val = ndn_forwarder_put_data(block_value, encoder.offset);
  CU_ASSERT_EQUAL(ret_val, 0);

  while (!forwarder_put_data_received) {}
  CU_ASSERT_TRUE(forwarder_put_data_received);
}

int test_sign_data(const char* id, uint32_t id_len, ndn_encoder_t* encoder, ndn_data_t* data) {
  ndn_ecc_prv_t prv_key;
  ndn_ecc_prv_init(&prv_key, test_ecc_secp256r1_private_raw_1, sizeof(test_ecc_secp256r1_private_raw_1), NDN_ECDSA_CURVE_SECP256R1, 1234);
  ndn_name_t identity;
  int ret_val = ndn_name_from_string(&identity, id, id_len);
  CU_ASSERT_EQUAL(ret_val, 0);
  if (ret_val != 0)
  {
    _current_forwarder_test_all_calls_succeeded = false;
    print_error(_current_test_name, "_run_forwarder_test", "ndn_name_from_string", ret_val);
  }
  ret_val = ndn_data_tlv_encode_ecdsa_sign(encoder, data, &identity, &prv_key);
  CU_ASSERT_EQUAL(ret_val, 0);
  if (ret_val != 0)
  {
    _current_forwarder_test_all_calls_succeeded = false;
    print_error(_current_test_name, "_run_forwarder_test", "ndn_data_tlv_encode_ecdsa_sign", ret_val);
  }
  return 0;
}

void forwarder_pointer_test()
{
  ndn_forwarder_init();

  const ndn_forwarder_t* forwarder;
  forwarder = ndn_forwarder_get();

  // prepare dummy face
  ndn_dummy_face_t *dummy_face;
  dummy_face = ndn_dummy_face_construct();

  char prefix_string[] = "/test3";
  ndn_name_t prefix;
  int ret_val = ndn_name_from_string(&prefix, prefix_string, sizeof(prefix_string));
  CU_ASSERT_EQUAL(ret_val, 0);
  uint8_t tmp_name_buf[256] = {0};
  ndn_encoder_t tmp_name_encoder;
  encoder_init(&tmp_name_encoder, tmp_name_buf, 256);
  ndn_name_tlv_encode(&tmp_name_encoder, &prefix);
  ndn_fib_entry_t *fib_entry;
  fib_entry = ndn_fib_find(forwarder->fib, tmp_name_buf, tmp_name_encoder.offset);
  CU_ASSERT_PTR_NULL(fib_entry);

  // add route
  ret_val = ndn_forwarder_add_route_by_str(&dummy_face->intf, "/test3", strlen("/test3"));
  CU_ASSERT_EQUAL(ret_val, 0);

  fib_entry = ndn_fib_find(forwarder->fib, tmp_name_buf, tmp_name_encoder.offset);
  CU_ASSERT_PTR_NOT_NULL(fib_entry);

  CU_PASS("The forwarder pointer test was successful");
  return;
}

void add_forwarder_test_suite()
{
  CU_pSuite pSuite = NULL;

  /* add a suite to the registry */
  pSuite = CU_add_suite("Forwarder Test", NULL, NULL);
  if (NULL == pSuite)
  {
    CU_cleanup_registry();
    // return CU_get_error();
    return;
  }
  if (NULL == CU_add_test(pSuite, "forwarder_tests", (void (*)(void))run_forwarder_tests) ||
      NULL == CU_add_test(pSuite, "forwarder_put_data_test", forwarder_put_data_test) ||
      NULL == CU_add_test(pSuite, "forwarder_pointer_test", forwarder_pointer_test))
  {
    CU_cleanup_registry();
    // return CU_get_error();
    return;
  }
}