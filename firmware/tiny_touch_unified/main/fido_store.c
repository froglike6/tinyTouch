#include "fido_store.h"
#include "fido_crypto.h"
#include "fido_platform.h"

#include <stdio.h>
#include <string.h>

static fido_state_t state;
static fido_resident_t residents[FIDO_MAX_RESIDENT_CREDENTIALS];

static void resident_key(size_t index, char key[8]) {
  snprintf(key, 8, "rk%02u", (unsigned)index);
}

bool fido_store_reset(void) {
  fido_state_t replacement = {.version = 1};
  if (!fido_crypto_random(replacement.master_key, 32)) return false;
  bool ok = fido_platform_erase() &&
      fido_platform_write("state", &replacement, sizeof(replacement));
  fido_crypto_wipe(&state, sizeof(state));
  fido_crypto_wipe(residents, sizeof(residents));
  if (ok) state = replacement;
  fido_crypto_wipe(&replacement, sizeof(replacement));
  return ok;
}

bool fido_store_init(void) {
  size_t size = sizeof(state);
  fido_storage_result_t result = fido_platform_read("state", &state, &size);
  if (result == FIDO_STORAGE_NOT_FOUND) {
    // Only an empty namespace can acquire a new wrapping key. A missing key
    // alongside credentials is corruption, not permission to discard them.
    for (size_t i = 0; i < FIDO_MAX_RESIDENT_CREDENTIALS; i++) {
      char key[8];
      resident_key(i, key);
      size_t record_size = sizeof(residents[i]);
      if (fido_platform_read(key, &residents[i], &record_size) !=
          FIDO_STORAGE_NOT_FOUND) return false;
    }
    return fido_store_reset();
  }
  if (result != FIDO_STORAGE_OK || size != sizeof(state) || state.version != 1)
    return false;
  memset(residents, 0, sizeof(residents));
  for (size_t i = 0; i < FIDO_MAX_RESIDENT_CREDENTIALS; i++) {
    char key[8];
    resident_key(i, key);
    size = sizeof(residents[i]);
    result = fido_platform_read(key, &residents[i], &size);
    if (result == FIDO_STORAGE_NOT_FOUND) continue;
    const fido_resident_t *record = &residents[i];
    uint8_t private_key[32];
    bool valid = result == FIDO_STORAGE_OK && size == sizeof(*record) &&
        record->version == 1 && record->credential_id[0] == FIDO_CREDENTIAL_RESIDENT &&
        record->user_id_length > 0 &&
        record->user_id_length <= FIDO_USER_ID_MAX &&
        record->user_name[FIDO_USER_NAME_MAX] == '\0' &&
        record->created > 0 && record->created <= state.counter &&
        fido_crypto_unwrap(&state, record->rp_hash, record->credential_id, private_key);
    fido_crypto_wipe(private_key, sizeof(private_key));
    if (!valid) return false;
  }
  return true;
}

bool fido_store_next_counter(uint32_t *counter) {
  if (state.counter == UINT32_MAX || fido_platform_cancelled()) return false;
  fido_state_t replacement = state;
  replacement.counter++;
  bool ok = fido_platform_write("state", &replacement, sizeof(replacement));
  if (ok) {
    state.counter = replacement.counter;
    *counter = state.counter;
  }
  fido_crypto_wipe(&replacement, sizeof(replacement));
  return ok;
}

const fido_state_t *fido_store_state(void) { return &state; }

const fido_resident_t *fido_store_resident(size_t index) {
  return index < FIDO_MAX_RESIDENT_CREDENTIALS && residents[index].version == 1 ?
      &residents[index] : NULL;
}

size_t fido_store_resident_count(void) {
  size_t count = 0;
  for (size_t i = 0; i < FIDO_MAX_RESIDENT_CREDENTIALS; i++)
    if (residents[i].version == 1) count++;
  return count;
}

int fido_store_resident_slot(const uint8_t rp_hash[32], const uint8_t *user_id,
                              size_t user_id_size) {
  int free_slot = -1;
  for (size_t i = 0; i < FIDO_MAX_RESIDENT_CREDENTIALS; i++) {
    const fido_resident_t *record = &residents[i];
    if (record->version == 0) { if (free_slot < 0) free_slot = (int)i; continue; }
    if (memcmp(record->rp_hash, rp_hash, 32) == 0 &&
        record->user_id_length == user_id_size &&
        memcmp(record->user_id, user_id, user_id_size) == 0) return (int)i;
  }
  return free_slot;
}

bool fido_store_save_resident(size_t index, const fido_resident_t *resident) {
  if (index >= FIDO_MAX_RESIDENT_CREDENTIALS || fido_platform_cancelled()) return false;
  char key[8];
  resident_key(index, key);
  if (!fido_platform_write(key, resident, sizeof(*resident))) return false;
  residents[index] = *resident;
  return true;
}
