/*
 * Copyright (C) 2018-2020
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN-LITE authors and contributors.
 */

#include "name.h"

void
ndn_name_print(const ndn_name_t* name)
{
  for (int i = 0; i < name->components_size; i++) {
    name_component_print(&name->components[i]);
  }
  printf("\n");
}

void
ndn_name_init(ndn_name_t *name)
{
  name->components_size = 0;
  for (int i = 0; i < NDN_NAME_COMPONENTS_SIZE; i++) {
    name->components[i].size = NDN_FWD_INVALID_NAME_COMPONENT_SIZE;
  }
}

int
ndn_name_tlv_decode(ndn_decoder_t* decoder, ndn_name_t* name)
{
  int ret_val = -1;
  uint32_t type = 0;
  ret_val = decoder_get_type(decoder, &type);
  if (ret_val != NDN_SUCCESS) return ret_val;
  if (type != TLV_Name) {
    return NDN_WRONG_TLV_TYPE;
  }
  uint32_t length = 0;
  ret_val = decoder_get_length(decoder, &length);
  if (ret_val != NDN_SUCCESS) return ret_val;
  uint32_t start_offset = decoder->offset;
  int counter = 0;
  while (decoder->offset < start_offset + length) {
    if (counter >= NDN_NAME_COMPONENTS_SIZE)
      return NDN_OVERSIZE;
    int result = name_component_tlv_decode(decoder, &name->components[counter]);
    if (result < 0)
      return result;
    ++counter;
  }
  name->components_size = counter;
  return 0;
}

int
ndn_name_from_block(ndn_name_t* name, const uint8_t* block_value, uint32_t block_size)
{
  ndn_decoder_t decoder;
  decoder_init(&decoder, block_value, block_size);
  return ndn_name_tlv_decode(&decoder, name);
}

int
ndn_name_from_string(ndn_name_t *name, const char* string, uint32_t size)
{
  int ret_val = -1;
  name->components_size = 0;

  uint32_t i = 0;
  int last_divider = 0;
  if (string[i] != '/') {
    last_divider = -1;
  }
  ++i;
  while (i < size) {
    if (string[i] == '/') {
      name_component_t component;
      ret_val = name_component_from_string(&component, &string[last_divider + 1], i - last_divider - 1);
      if (ret_val != NDN_SUCCESS) return ret_val;
      int result = ndn_name_append_component(name, &component);
      if (result < 0) {
        return result;
      }
      last_divider = i;
    }
    if (i == size - 1) {
      name_component_t component;
      ret_val = name_component_from_string(&component, &string[last_divider + 1], i - last_divider);
      if (ret_val != NDN_SUCCESS) return ret_val;
      int result = ndn_name_append_component(name, &component);
      if (result < 0) {
        return result;
      }
    }
    ++i;
  }
  return 0;
}

int
ndn_name_append_component(ndn_name_t *name, const name_component_t* component)
{
  if (name->components_size + 1 <= NDN_NAME_COMPONENTS_SIZE) {
    memcpy(name->components + name->components_size, component, sizeof(name_component_t));
    name->components_size++;
    return 0;
  }
  else
    return NDN_OVERSIZE;
}

int
ndn_name_append_bytes_component(ndn_name_t* name, const uint8_t* value, uint32_t size)
{
  if (name->components_size + 1 <= NDN_NAME_COMPONENTS_SIZE) {
    name_component_t comp;
    name_component_from_buffer(&comp, TLV_GenericNameComponent, value, size);
    ndn_name_append_component(name, &comp);
    return 0;
  }
  else
    return NDN_OVERSIZE;
}

int
ndn_name_append_string_component(ndn_name_t* name, const char* string, uint32_t size)
{
  if (name->components_size + 1 <= NDN_NAME_COMPONENTS_SIZE) {
    name_component_t comp;
    name_component_from_string(&comp, string, size);
    ndn_name_append_component(name, &comp);
    return 0;
  }
  else
    return NDN_OVERSIZE;
}

int
ndn_name_append_name(ndn_name_t* lhs, const ndn_name_t* rhs)
{
  if (lhs->components_size + rhs->components_size <= NDN_NAME_COMPONENTS_SIZE) {
    for (int i = 0; i < rhs->components_size; i++) {
      memcpy(&lhs->components[lhs->components_size], &rhs->components[i], sizeof(name_component_t));
      lhs->components_size++;
    }
    return 0;
  }
  else
    return NDN_OVERSIZE;
}

int
ndn_name_append_keyid(ndn_name_t* name, uint32_t key_id)
{
  if (name->components_size + 1 <= NDN_NAME_COMPONENTS_SIZE) {
    uint8_t bytes[4];
    ndn_encoder_t encoder;
    encoder_init(&encoder, bytes, 4);
    encoder_append_uint32_value(&encoder, key_id);
    name_component_t comp;
    name_component_from_buffer(&comp, TLV_GenericNameComponent, bytes, 4);
    ndn_name_append_component(name, &comp);
    return 0;
  }
  else
    return NDN_OVERSIZE;
}

int
ndn_name_tlv_encode(ndn_encoder_t* encoder, const ndn_name_t *name)
{
  int ret_val = -1;
  int block_sizes[name->components_size];
  ret_val = encoder_append_type(encoder, TLV_Name);
  if (ret_val != NDN_SUCCESS) return ret_val;
  size_t value_size = 0;
  for (size_t i = 0; i < name->components_size; i++) {
    block_sizes[i] = name_component_probe_block_size(&name->components[i]);
    value_size += block_sizes[i];
  }
  ret_val = encoder_append_length(encoder, value_size);
  if (ret_val != NDN_SUCCESS) return ret_val;

  for (size_t i = 0; i < name->components_size; i++) {
    int result = name_component_tlv_encode(encoder, &name->components[i]);
    if (result < 0)
      return result;
  }
  return 0;
}

int
ndn_name_compare(const ndn_name_t* lhs, const ndn_name_t* rhs)
{
  if (lhs->components_size != rhs->components_size) return -1;
  else {
    int result = 0;
    for (uint8_t i = 0; i < lhs->components_size; i++) {
      result = name_component_compare(&lhs->components[i], &rhs->components[i]);
      if (result != 0) return -1;
    }
    return 0;
  }
}

int
ndn_name_compare_sub_names(const ndn_name_t* lhs, int lhs_b, int lhs_e,
			   const ndn_name_t* rhs, int rhs_b, int rhs_e) {
  if (lhs_e-lhs_b != rhs_e-rhs_b) return -1;
  else {
    int result = 0;
    for (uint8_t i = 0; i < lhs_e-lhs_b; i++) {
      result = name_component_compare(&lhs->components[lhs_b+i], &rhs->components[rhs_b+i]);
      if (result != 0) return -1;
    }
    return 0;
  }
}

int
ndn_name_is_prefix_of(const ndn_name_t* lhs, const ndn_name_t* rhs)
{
  int result = 0;
  uint8_t i;

  if (lhs->components_size > rhs->components_size) {
    return 1;
  }
  else {
    result = 0;
    for (i = 0; i < lhs->components_size; i++) {
      result = name_component_compare(&lhs->components[i], &rhs->components[i]);
      if (result != 0) return 1;
    }
    return 0;
  }
}

int
ndn_name_compare_block(const uint8_t* lhs_block_value, uint32_t lhs_block_size,
                       const uint8_t* rhs_block_value, uint32_t rhs_block_size)
{
  if (lhs_block_value == NULL || lhs_block_size <= 0) return NDN_OVERSIZE_VAR;
  if (rhs_block_value == NULL || rhs_block_size <= 0) return NDN_OVERSIZE_VAR;

  ndn_decoder_t lhs_decoder, rhs_decoder;
  decoder_init(&lhs_decoder, lhs_block_value, lhs_block_size);
  decoder_init(&rhs_decoder, rhs_block_value, rhs_block_size);
  uint32_t probe = 0, retval = 0;

  /* check left name type */
  decoder_get_type(&lhs_decoder, &probe);
  if (probe != TLV_Name) return NDN_WRONG_TLV_TYPE;

  /* check right name type */
  decoder_get_type(&rhs_decoder, &probe);
  if (probe != TLV_Name) return NDN_WRONG_TLV_TYPE;

  /* read left name length */
  decoder_get_length(&lhs_decoder, &probe);
  if (retval != NDN_SUCCESS) return NDN_WRONG_TLV_LENGTH;

  /* read right name length */
  decoder_get_length(&rhs_decoder, &probe);
  if (retval != NDN_SUCCESS) return NDN_WRONG_TLV_LENGTH;

  int r = memcmp(lhs_decoder.input_value + lhs_decoder.offset,
                 rhs_decoder.input_value + rhs_decoder.offset,
                 lhs_decoder.input_size - lhs_decoder.offset <
                 rhs_decoder.input_size - rhs_decoder.offset ?
                 lhs_decoder.input_size - lhs_decoder.offset :
                 rhs_decoder.input_size - rhs_decoder.offset);

  if (r < 0) return -1;
  else if (r > 0) return 1;
  else {
      if (lhs_decoder.input_size - lhs_decoder.offset <
          rhs_decoder.input_size - rhs_decoder.offset)
        return -2;
      else if (lhs_decoder.input_size - lhs_decoder.offset >
               rhs_decoder.input_size - rhs_decoder.offset)
             return 2;
      else return 0;
  }
}
