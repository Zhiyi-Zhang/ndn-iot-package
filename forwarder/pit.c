/*
 * Copyright (C) 2018-2020
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN-LITE authors and contributors.
 */
#define ENABLE_NDN_LOG_INFO 0
#define ENABLE_NDN_LOG_DEBUG 0
#define ENABLE_NDN_LOG_ERROR 1
#include "pit.h"
#include "../util/msg-queue.h"
#include "../util/logger.h"

static inline void
ndn_pit_entry_reset(ndn_pit_entry_t* self){
  self->nametree_id = NDN_INVALID_ID;
  self->last_time = 0;
  self->express_time = 0;
  self->incoming_faces = 0;
  self->outgoing_faces = 0;
  self->on_data = NULL;
  self->on_timeout = NULL;
  self->userdata = NULL;
  // Don't reset options.nonce here
}

static void ndn_pit_timeout(void *selfptr, size_t param_len, void *param){
  (void) param_len, param;
  ndn_pit_t* self = (ndn_pit_t*)selfptr;
  ndn_table_id_t i;
  ndn_time_ms_t now = ndn_time_now_ms();
  ndn_on_timeout_func on_timeout = NULL;
  void* userdata = NULL;

  for(i = 0; i < self->capacity; i ++){
    if(self->slots[i].nametree_id == NDN_INVALID_ID){
      continue;
    }

    // User timeout
    if(self->slots[i].on_data != NULL){
      if(now - self->slots[i].express_time > self->slots[i].options.lifetime){
        on_timeout = self->slots[i].on_timeout;
        userdata = self->slots[i].userdata;
        
        self->slots[i].on_timeout = NULL;
        self->slots[i].on_data = NULL;
        self->slots[i].userdata = NULL;
        self->slots[i].express_time = 0;
        self->slots[i].outgoing_faces = 0;

        if(on_timeout){
          on_timeout(userdata);
        }
      }
    }
    // PIT timeout
    if((now > self->slots[i].last_time) &&
       (now - self->slots[i].last_time > self->slots[i].options.lifetime))
    {
      ndn_pit_remove_entry(self, &self->slots[i]);
    }
  }

  ndn_msgqueue_post(self, ndn_pit_timeout, 0, NULL);
}

void
ndn_pit_init(void* memory, ndn_table_id_t capacity, ndn_nametree_t* nametree){
  ndn_table_id_t i;
  ndn_pit_t* self = (ndn_pit_t*)memory;
  self->capacity = capacity;
  self->nametree = nametree;
  for(i = 0; i < capacity; i ++){
    ndn_pit_entry_reset(&self->slots[i]);
    self->slots[i].options.nonce = 0;
  }

  ndn_msgqueue_post(self, ndn_pit_timeout, 0, NULL);
}

void
ndn_pit_remove_entry(ndn_pit_t* self, ndn_pit_entry_t* entry){
  ndn_nametree_at(self->nametree, entry->nametree_id)->pit_id = NDN_INVALID_ID;
  ndn_pit_entry_reset(entry);
}

static inline void
ndn_pit_remove_entry_if_empty(ndn_pit_t* self, ndn_pit_entry_t* entry){
  if(entry->nametree_id == NDN_INVALID_ID){
    return;
  }
  if(entry->incoming_faces == 0 &&
     entry->on_data == NULL &&
     entry->on_timeout == NULL)
  {
    ndn_pit_remove_entry(self, entry);
  }
}

void
ndn_pit_unregister_face(ndn_pit_t* self, ndn_table_id_t face_id){
  for (ndn_table_id_t i = 0; i < self->capacity; ++i){
    self->slots[i].incoming_faces = bitset_unset(self->slots[i].incoming_faces, face_id);
    ndn_pit_remove_entry_if_empty(self, &self->slots[i]);
  }
}

static ndn_table_id_t
ndn_pit_add_new_entry(ndn_pit_t* pit , int nametree_id){
  ndn_table_id_t i;
  for (i = 0; i < pit->capacity; ++i) {
    if (pit->slots[i].nametree_id == NDN_INVALID_ID) {
      ndn_pit_entry_reset(&pit->slots[i]);
      pit->slots[i].nametree_id = nametree_id;
      return i;
    }
  }
  return NDN_INVALID_ID;
}

ndn_pit_entry_t*
ndn_pit_find_or_insert(ndn_pit_t* self, uint8_t* name, size_t length){
  nametree_entry_t* entry = ndn_nametree_find_or_insert(self->nametree, name, length);
  if(entry == NULL){
    return NULL;
  }
  if(entry->pit_id == NDN_INVALID_ID){
    entry->pit_id = ndn_pit_add_new_entry(self, ndn_nametree_getid(self->nametree, entry));
    NDN_LOG_DEBUG("[PIT] Add a new PIT entry\n");
    if(entry->pit_id == NDN_INVALID_ID){
      return NULL;
    }
  }
  return &self->slots[entry->pit_id];
}

ndn_pit_entry_t*
ndn_pit_find(ndn_pit_t* self, uint8_t* prefix, size_t length)
{
  nametree_entry_t* entry = ndn_nametree_find(self->nametree, prefix, length);
  if (entry == NULL || entry->pit_id == NDN_INVALID_ID) {
    return NULL;
  }
  return &self->slots[entry->pit_id];
}

ndn_pit_entry_t*
ndn_pit_prefix_match(ndn_pit_t* self, uint8_t* prefix, size_t length)
{
  nametree_entry_t* entry = ndn_nametree_prefix_match(self->nametree, prefix, length, NDN_NAMETREE_PIT_TYPE);
  if (entry == NULL || entry->pit_id == NDN_INVALID_ID) {
    return NULL;
  }
  return &self->slots[entry->pit_id];
}
