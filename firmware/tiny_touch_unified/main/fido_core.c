#include "fido_core.h"
#include "fido_crypto.h"
#include "fido_platform.h"
#include "fido_response.h"
#include "fido_store.h"

#include <string.h>

static bool ready;
static uint32_t boot_time;
static bool reset_window_closed;
static struct {
  fido_request_t request;
  uint32_t channel;
  uint32_t last_time;
  uint8_t indices[FIDO_MAX_RESIDENT_CREDENTIALS];
  size_t count;
  size_t next;
  uint8_t flags;
} assertions;

void fido_core_invalidate(void) { memset(&assertions, 0, sizeof(assertions)); }

bool fido_core_init(void) {
  fido_core_invalidate();
  boot_time = fido_platform_time_ms();
  reset_window_closed = false;
  ready = fido_crypto_init() && fido_store_init();
  return ready;
}

bool fido_core_ready(void) { return ready; }

bool fido_core_reset(void) {
  fido_core_invalidate();
  ready = fido_store_reset();
  return ready;
}

size_t fido_core_resident_count(void) {
  return ready ? fido_store_resident_count() : 0;
}

static fido_status_t verify_user(void) {
  if (fido_platform_cancelled()) return FIDO_ERR_CANCELLED;
  if (!fido_platform_uv_configured()) return FIDO_ERR_OPERATION_DENIED;
  return fido_platform_verify_user();
}

static fido_status_t make_credential(const CborValue *map, uint8_t *response, size_t *size) {
  fido_request_t request;
  FIDO_TRY(fido_request_parse(map, true, &request));
  bool excluded = false;
  uint8_t id[FIDO_CREDENTIAL_ID_SIZE];
  CborValue list;
  if (fido_cbor_key(map, 5, &list))
    FIDO_TRY(fido_request_credential(&list, request.rp_hash, id, &excluded));
  FIDO_TRY(verify_user());
  if (excluded) return FIDO_ERR_CREDENTIAL_EXCLUDED;
  return fido_response_make(&request, response, size);
}

static fido_status_t get_assertion(uint32_t channel, const CborValue *map,
                                    uint8_t *response, size_t *size) {
  fido_request_t request;
  FIDO_TRY(fido_request_parse(map, false, &request));
  CborValue list;
  uint8_t id[FIDO_CREDENTIAL_ID_SIZE];
  bool found = false;
  bool allow_list = fido_cbor_key(map, 3, &list);
  if (allow_list) {
    FIDO_TRY(fido_request_credential(&list, request.rp_hash, id, &found));
    size_t list_size = 0;
    FIDO_CBOR_TRY(cbor_value_get_array_length(&list, &list_size));
    allow_list = list_size != 0;
  }
  if (!allow_list) {
    for (size_t i = 0; i < FIDO_MAX_RESIDENT_CREDENTIALS; i++) {
      const fido_resident_t *record = fido_store_resident(i);
      if (record && memcmp(record->rp_hash, request.rp_hash, 32) == 0) {
        size_t position = assertions.count++;
        // Present the most recently created credential first.
        while (position > 0 && fido_store_resident(assertions.indices[position - 1])->created <
            record->created) {
          assertions.indices[position] = assertions.indices[position - 1];
          position--;
        }
        assertions.indices[position] = (uint8_t)i;
      }
    }
    found = assertions.count != 0;
  }
  uint8_t flags = 0;
  if (request.presence || request.verification) {
    FIDO_TRY(verify_user());
    // A successful enrolled fingerprint supplies both presence and verification.
    flags = 0x05;
  }
  if (!found) return FIDO_ERR_NO_CREDENTIALS;
  const fido_resident_t *resident = NULL;
  if (!allow_list) {
    resident = fido_store_resident(assertions.indices[0]);
    memcpy(id, resident->credential_id, sizeof(id));
  }
  FIDO_TRY(fido_response_assert(&request, id, resident, flags,
                               allow_list ? 0 : assertions.count, response, size));
  if (!allow_list && assertions.count > 1) {
    assertions.request = request;
    assertions.channel = channel;
    assertions.last_time = fido_platform_time_ms();
    assertions.next = 1;
    assertions.flags = flags;
  }
  return FIDO_OK;
}

static fido_status_t next_assertion(uint32_t channel, uint8_t *response, size_t *size) {
  if (!assertions.next || assertions.next >= assertions.count ||
      assertions.channel != channel ||
      (uint32_t)(fido_platform_time_ms() - assertions.last_time) > 30000)
    return FIDO_ERR_NOT_ALLOWED;
  const fido_resident_t *record = fido_store_resident(assertions.indices[assertions.next]);
  FIDO_TRY(fido_response_assert(&assertions.request, record->credential_id,
                               record, assertions.flags, 0, response, size));
  assertions.next++;
  assertions.last_time = fido_platform_time_ms();
  return FIDO_OK;
}

static fido_status_t dispatch(uint32_t channel, const uint8_t *request,
                               size_t request_size, uint8_t *response, size_t *size) {
  if (request[0] == 4 || request[0] == 7 || request[0] == 8) {
    if (request_size != 1) return FIDO_ERR_INVALID_LENGTH;
    if (request[0] == 4) return fido_response_info(response, size);
    if (request[0] == 8) return next_assertion(channel, response, size);
    if (reset_window_closed) return FIDO_ERR_NOT_ALLOWED;
    FIDO_TRY(verify_user());
    if (fido_platform_cancelled()) return FIDO_ERR_CANCELLED;
    *size = 0;
    return fido_core_reset() ? FIDO_OK : FIDO_ERR_OTHER;
  }
  if (request[0] != 1 && request[0] != 2) return FIDO_ERR_INVALID_COMMAND;
  CborParser parser;
  CborValue map;
  FIDO_TRY(fido_cbor_parse(request + 1, request_size - 1, &parser, &map));
  if (request[0] == 1) return make_credential(&map, response, size);
  return get_assertion(channel, &map, response, size);
}

size_t fido_core_request(uint32_t channel, const uint8_t *request, size_t request_size,
                          uint8_t response[FIDO_RESPONSE_MAX]) {
  if (request_size == 0 || request_size > FIDO_MAX_MESSAGE) {
    response[0] = FIDO_ERR_INVALID_LENGTH;
    return 1;
  }
  if (request[0] != 8) fido_core_invalidate();
  if ((uint32_t)(fido_platform_time_ms() - boot_time) > 10000) reset_window_closed = true;
  size_t size = FIDO_RESPONSE_MAX - 1;
  fido_status_t status = ready ? dispatch(channel, request, request_size, response + 1, &size) :
      FIDO_ERR_OTHER;
  if (fido_platform_cancelled()) status = FIDO_ERR_CANCELLED;
  response[0] = (uint8_t)status;
  if (status != FIDO_OK) {
    fido_core_invalidate();
    fido_crypto_wipe(response + 1, FIDO_RESPONSE_MAX - 1);
    return 1;
  }
  return size + 1;
}
