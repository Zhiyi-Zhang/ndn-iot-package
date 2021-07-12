/*
 * Copyright (C) 2018-2020
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN-LITE authors and contributors.
 */

#ifndef NDN_ERROR_CODE_H
#define NDN_ERROR_CODE_H

#include <inttypes.h>

/** @defgroup NDNErrorCode NDN Error Codes
 * @brief A collection of error codes in groups.
 * A page listing all codes can be found in ndn-error-code.h.
 * @sa ndn-error-code.h
 * @{ */

/** The operation completed successfully.
 */
#define NDN_SUCCESS 0

/** @defgroup NDNErrorCodeGeneral General Error Types
 * @ingroup NDNErrorCode
 * @{ */

/** The object given is larger than expected.
 *
 * This error can be caused by multiple reasons. Generally caused by an input parameter
 * whose size is larger than the corresponding value defined in ndn-constants.h.
 */
#define NDN_OVERSIZE -10

/** The format of the name string specified is invalid.
 *
 * A uri string of a name should start with "/".
 */
#define NDN_NAME_INVALID_FORMAT -11

/** The Type specified cannot be recognized.
 */
#define NDN_WRONG_TLV_TYPE -12

/** The Length specified differs from expected.
 *
 * This can be due to one of the following reasons:
 *  - The input Length for a TLV block is not 1, 2, 4 or 8, as the Spec requires.
 *  - The Type of the TLV block given requires a fixed Length different from the Length it has.
 *  - The function expects an input block to be a single TLV block, while the Length is less than
 *      the buffer size plus TL's sizes.
 */
#define NDN_WRONG_TLV_LENGTH -13

/** Truncation due to insufficient buffer.
 *
 * The operation specified requires more memory than the buffer variable given.
 * For example, passing <tt>{FD 01}</tt> to a TLV block parameter will cause this error,
 * because <tt>FD</tt> indicates the Type is encoded in the following 2 bytes, but there's
 * not enough space.
 */
#define NDN_OVERSIZE_VAR -14

/** The operation faild due to specific reason.
 *
 * Reserved. See the function called.
 */
#define NDN_TLV_OP_FAILED -15

/** Pass NULL to a non-optional parameter.
 */
#define NDN_INVALID_POINTER -16

/** The format of a specified TLV block is different from expectation.
 *
 * Different between #NDN_WRONG_TLV_TYPE, #NDN_UNSUPPORTED_FORMAT is due to unexpected
 * type inside a TLV block. For example, when a function requires a Interest parameter @c interest
 * - If a Name is passed, it will return #NDN_WRONG_TLV_TYPE.
 * - If an Interest with one component having a unknown TLV type is passed, return #NDN_WRONG_TLV_TYPE.
 * - If an Interest whose first component is not Name is passed, return #NDN_UNSUPPORTED_FORMAT.
 */
#define NDN_UNSUPPORTED_FORMAT -17

#define NDN_INVALID_ARG -18
#define NDN_STATE_NOT_INITIALIZED -19


/* @} */

/** @defgroup NDNErrorCodeSecurity Security Errors
 * @ingroup NDNErrorCode
 * @{ */
#define NDN_SEC_WRONG_KEY_SIZE -22
#define NDN_SEC_WRONG_SIG_SIZE -23
#define NDN_SEC_DISABLED_FEATURE -24
#define NDN_SEC_CRYPTO_ALGO_FAILURE -25
#define NDN_SEC_UNSUPPORT_CRYPTO_ALGO -26
#define NDN_SEC_UNSUPPORT_SIGN_TYPE -26
#define NDN_SEC_WRONG_AES_SIZE -27
#define NDN_SEC_INIT_FAILURE -28
#define NDN_SEC_FAIL_VERIFY_SIG -29
#define NDN_SEC_SIGNED_INTEREST_INVALID_DIGEST -30
#define NDN_SEC_WRONG_INPUT_SIZE -31
/* @} */

/** @defgroup NDNErrorCodeFragmentation Fragmentation Errors
 * @ingroup NDNErrorCode
 * @{ */
#define NDN_FRAG_NO_MORE_FRAGS -40
#define NDN_FRAG_OUT_OF_ORDER -41
#define NDN_FRAG_NO_MEM -42
#define NDN_FRAG_WRONG_IDENTIFIER -43
/* @} */

/** @defgroup NDNErrorCodeForwarder Forwarder Errors
 * @ingroup NDNErrorCode
 * @{ */

/** The operation has no effect.
 */
#define NDN_FWD_NO_EFFECT -50

/** The FaceTable is full.
 */
#define NDN_FWD_FACE_TABLE_FULL -51

/** The PIT is full.
 */
#define NDN_FWD_PIT_FULL -52

/** The FIB is full.
 */
#define NDN_FWD_FIB_FULL -53

/** The face has a wrong ID.
 */
#define NDN_FWD_INVALID_FACE -54

/** The Interest is rejected.
 *
 * - The Interest has a same nonce as previous one, indicating a routing loop.
 * - The Interest's hop limit comes to 0.
 * @note Different from NFD, NDN-Lite only records one nonce.
 *       Thus, not all routing loop can be avoided.
 */
#define NDN_FWD_INTEREST_REJECTED -55

/** No route to forward a specified packet.
 *
 * The incoming face doesn't count.
 */
#define NDN_FWD_NO_ROUTE -56

/** The message queue is full.
 */
#define NDN_FWD_MSGQUEUE_FULL -57
/* @} */

/** @defgroup NDNErrorCodeFace Face Errors
 * @ingroup NDNErrorCode
 * @{ */
#define NDN_FWD_FACE_DOWN -60
/* @} */

/** @defgroup NDNErrorCodeSD Service Discovery Errors
 * @ingroup NDNErrorCode
 * @{ */
#define NDN_SD_NOT_INITIALIZED -61
#define NDN_SD_NO_MATCH_SERVCE -62
/* @} */

/** @defgroup NDNErrorCodeAC Access Control Errors
 * @ingroup NDNErrorCode
 * @{ */
#define NDN_AC_NOT_INITIALIZED -70
#define NDN_AC_KEY_NOT_OBTAINED -71
#define NDN_AC_KEY_EXPIRED -72
#define NDN_AC_KEY_NOT_FOUND -73
/* @} */

/** @defgroup NDNErrorCodeSign Sign-on Protocol Errors
 * @ingroup NDNErrorCode
 * @{ */
#define NDN_SIGN_ON_BASIC_CLIENT_INIT_FAILED_UNRECOGNIZED_VARIANT -101
#define NDN_SIGN_ON_BASIC_CLIENT_INIT_FAILED_TO_SET_SEC_INTF -102
#define NDN_SIGN_ON_CNSTRCT_BTSTRP_RQST_BUFFER_TOO_SHORT -103
#define NDN_SIGN_ON_CNSTRCT_BTSTRP_RQST_ENCODING_FAILED -104
#define NDN_SIGN_ON_CNSTRCT_BTSTRP_RQST_FAILED_TO_GENERATE_N1_KEYPAIR -105
#define NDN_SIGN_ON_CNSTRCT_BTSTRP_RQST_FAILED_TO_GENERATE_SIG_PAYLOAD_HASH -106
#define NDN_SIGN_ON_CNSTRCT_BTSTRP_RQST_FAILED_TO_GENERATE_SIG -107
#define NDN_SIGN_ON_PRCS_BTSTRP_RQST_RSPNS_FAILED_TO_VERIFY_SIGNATURE -108
#define NDN_SIGN_ON_PRCS_BTSTRP_RQST_RSPNS_FAILED_TO_PARSE_TLV_BTSTRP_RQST_RSPNS -109
#define NDN_SIGN_ON_PRCS_BTSTRP_RQST_RSPNS_FAILED_TO_PARSE_TLV_SIG -110
#define NDN_SIGN_ON_PRCS_BTSTRP_RQST_RSPNS_FAILED_TO_PARSE_TLV_TRUST_ANCHOR_CERT -111
#define NDN_SIGN_ON_PRCS_BTSTRP_RQST_RSPNS_FAILED_TO_PARSE_TLV_N2_PUB -112
#define NDN_SIGN_ON_PRCS_BTSTRP_RQST_RSPNS_FAILED_TO_GENERATE_KT -113
#define NDN_SIGN_ON_CNSTRCT_CERT_RQST_BUFFER_TOO_SHORT -114
#define NDN_SIGN_ON_CNSTRCT_CERT_RQST_ENCODING_FAILED -115
#define NDN_SIGN_ON_CNSTRCT_CERT_RQST_FAILED_TO_GENERATE_N2_PUB_HASH -116
#define NDN_SIGN_ON_CNSTRCT_CERT_RQST_FAILED_TO_GENERATE_TRUST_ANCHOR_CERT_HASH -117
#define NDN_SIGN_ON_CNSTRCT_CERT_RQST_FAILED_TO_GENERATE_SIG_PAYLOAD_HASH -118
#define NDN_SIGN_ON_CNSTRCT_CERT_RQST_FAILED_TO_GENERATE_SIG -119
#define NDN_SIGN_ON_PRCS_CERT_RQST_RSPNS_FAILED_TO_VERIFY_SIGNATURE -120
#define NDN_SIGN_ON_PRCS_CERT_RQST_RSPNS_FAILED_TO_PARSE_TLV_CERT_RQST_RSPNS -121
#define NDN_SIGN_ON_PRCS_CERT_RQST_RSPNS_FAILED_TO_PARSE_TLV_KD_PUB_CERT -122
#define NDN_SIGN_ON_PRCS_CERT_RQST_RSPNS_FAILED_TO_PARSE_TLV_KD_PRI_ENC -123
#define NDN_SIGN_ON_PRCS_CERT_RQST_RSPNS_FAILED_TO_PARSE_TLV_SIG -124
#define NDN_SIGN_ON_PRCS_CERT_RQST_RSPNS_FAILED_TO_DECRYPT_KD_PRI -125
#define NDN_SIGN_ON_CNSTRCT_FIN_MSG_BUFFER_TOO_SHORT -126
#define NDN_SIGN_ON_CNSTRCT_FIN_MSG_ENCODING_FAILED -127
#define NDN_SIGN_ON_CNSTRCT_FIN_MSG_FAILED_TO_GENERATE_SIG_PAYLOAD_HASH -128
#define NDN_SIGN_ON_CNSTRCT_FIN_MSG_FAILED_TO_GENERATE_SIG -129
#define NDN_SIGN_ON_BASIC_SET_SEC_INTF_SUCCESS -130
#define NDN_SIGN_ON_BASIC_SET_SEC_INTF_FAILURE -131
#define NDN_SIGN_ON_BASIC_CLIENT_NRF_SDK_BLE_CONSTRUCT_FAILED_TO_INITIALIZE_SIGN_ON_BASIC_CLIENT -132
/* @} */

/** @defgroup NDNErrorCodeSignBLE Sign-on Protocol over BLE
 * @ingroup NDNErrorCode
 * @{ */
#define SIGN_ON_BASIC_CLIENT_BLE_FAILED_TO_SEND_BOOTSTRAPPING_REQUEST -129
#define SIGN_ON_BASIC_CLIENT_BLE_FAILED_TO_SEND_CERTIFICATE_REQUEST -130
#define SIGN_ON_BASIC_CLIENT_BLE_FAILED_TO_SEND_FINISH_MESSAGE -131
/* @} */

/** @defgroup NDNErrorCodeSignASN1 ASN.1 encoding / decoding
 * @ingroup NDNErrorCode
 * @{ */
#define NDN_ASN1_ECDSA_SIG_INVALID_SIZE -132
#define NDN_ASN1_ECDSA_SIG_BUFFER_TOO_SMALL -133
#define NDN_ASN1_ECDSA_SIG_FAILED_TO_PROBE_ASN1_INT_SIZE -134
#define NDN_ASN1_ECDSA_SIG_FAILED_TO_WRITE_ASN1_INT -135
#define NDN_ASN1_ECDSA_SIG_FAILED_TO_READ_ASN1_INT - 136
#define NDN_ASN1_ECDSA_SIG_FAILED_TO_READ_ASN1_SEQUENCE -137
/* @} */

/** @defgroup NDNErrorCodeSchematizedTrust Schematized trust related error codes
 * @ingroup NDNErrorCode
 * @{ */
#define NDN_TRUST_SCHEMA_PATTERN_COMPONENT_UNRECOGNIZED_TYPE -150
#define NDN_TRUST_SCHEMA_NAME_DID_NOT_MATCH -151
#define NDN_TRUST_SCHEMA_RULE_STORAGE_FULL -152
#define NDN_TRUST_SCHEMA_RULE_NAME_TOO_LONG -153
#define NDN_TRUST_SCHEMA_RULE_NOT_FOUND -154
#define NDN_TRUST_SCHEMA_DUPLICATE_RULE_NAME -155
#define NDN_TRUST_SCHEMA_PATTERN_STRING_ZERO_LENGTH -156
#define NDN_TRUST_SCHEMA_PATTERN_STRING_PREMATURE_TERMINATION -157
#define NDN_TRUST_SCHEMA_PATTERN_COMPONENT_PARSING_ERROR -158
#define NDN_TRUST_SCHEMA_PATTERN_INVALID_FORMAT -159
#define NDN_TRUST_SCHEMA_NUMBER_OF_SUBPATTERNS_EXCEEDS_LIMIT -160
#define NDN_TRUST_SCHEMA_RULE_REF_NOT_FOUND -161
#define NDN_TRUST_SCHEMA_RULE_REF_UNEQUAL_NUM_OF_SUBPATTERN_CAPTURES -162
#define NDN_TRUST_SCHEMA_PATTERN_COMPONENT_INVALID_SIZE -163
#define NDN_TRUST_SCHEMA_RULE_REFERENCING_NOT_IMPLEMENTED_YET -164
#define NDN_TRUST_SCHEMA_SUBPATTERN_INDEX_GREATER_THAN_NUMBER_OF_SUBPATTERN_CAPTURES -165
/* @} */

#endif // NDN_ERROR_CODE_H
