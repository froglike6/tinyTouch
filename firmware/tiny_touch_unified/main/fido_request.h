#pragma once

#include "fido_cbor.h"

typedef struct {
  uint8_t challenge[32];
  uint8_t rp_hash[32];
  uint8_t user_id[FIDO_USER_ID_MAX];
  size_t user_id_size;
  char user_name[FIDO_USER_NAME_MAX + 1];
  bool resident;
  bool presence;
  bool verification;
} fido_request_t;

fido_status_t fido_request_parse(const CborValue *map, bool creating,
                                  fido_request_t *request);
fido_status_t fido_request_credential(const CborValue *list,
                                      const uint8_t rp_hash[32], uint8_t id[61],
                                      bool *found);

#define FIDO_TRY(expression) do { \
  fido_status_t fido_error = (expression); \
  if (fido_error != FIDO_OK) return fido_error; \
} while (0)
