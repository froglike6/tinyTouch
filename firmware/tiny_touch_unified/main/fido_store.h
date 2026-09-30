#pragma once

#include "fido_types.h"

bool fido_store_init(void);
bool fido_store_reset(void);
bool fido_store_next_counter(uint32_t *counter);
const fido_state_t *fido_store_state(void);
const fido_resident_t *fido_store_resident(size_t index);
size_t fido_store_resident_count(void);
int fido_store_resident_slot(const uint8_t rp_hash[32], const uint8_t *user_id,
                              size_t user_id_size);
bool fido_store_save_resident(size_t index, const fido_resident_t *resident);
