#pragma once

#include "cbor.h"
#include "fido_types.h"

fido_status_t fido_cbor_parse(const uint8_t *data, size_t size,
                              CborParser *parser, CborValue *map);
bool fido_cbor_key(const CborValue *map, int key, CborValue *value);
bool fido_cbor_name(const CborValue *map, const char *name, CborValue *value);
fido_status_t fido_cbor_bytes(const CborValue *value, uint8_t *data,
                              size_t *size);
fido_status_t fido_cbor_text(const CborValue *value, char *data, size_t capacity);
bool fido_cbor_equals(const CborValue *value, const char *text);
fido_status_t fido_cbor_option(const CborValue *map, const char *name,
                               bool fallback, bool *result);

#define FIDO_CBOR_TRY(expression) do { \
  CborError fido_cbor_error = (expression); \
  if (fido_cbor_error != CborNoError) return FIDO_ERR_OTHER; \
} while (0)
