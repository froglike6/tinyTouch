#include "fido_cbor.h"

#include <string.h>

fido_status_t fido_cbor_parse(const uint8_t *data, size_t size,
                              CborParser *parser, CborValue *map) {
  if (cbor_parser_init(data, size, 0, parser, map) != CborNoError ||
      cbor_value_validate(map, CborValidateCanonicalFormat |
          CborValidateMapKeysAreUnique | CborValidateUtf8 |
          CborValidateNoTags | CborValidateCompleteData) != CborNoError)
    return FIDO_ERR_INVALID_CBOR;
  return cbor_value_is_map(map) ? FIDO_OK : FIDO_ERR_CBOR_TYPE;
}

bool fido_cbor_key(const CborValue *map, int key, CborValue *value) {
  if (!cbor_value_is_map(map)) return false;
  CborValue entry;
  if (cbor_value_enter_container(map, &entry) != CborNoError) return false;
  while (!cbor_value_at_end(&entry)) {
    int64_t number = 0;
    bool found = cbor_value_is_integer(&entry) &&
        cbor_value_get_int64_checked(&entry, &number) == CborNoError && number == key;
    if (cbor_value_advance(&entry) != CborNoError) return false;
    if (found) { *value = entry; return true; }
    if (cbor_value_advance(&entry) != CborNoError) return false;
  }
  return false;
}

bool fido_cbor_name(const CborValue *map, const char *name, CborValue *value) {
  if (!cbor_value_is_map(map)) return false;
  return cbor_value_map_find_value(map, name, value) == CborNoError &&
      cbor_value_is_valid(value);
}

fido_status_t fido_cbor_bytes(const CborValue *value, uint8_t *data, size_t *size) {
  if (!cbor_value_is_byte_string(value)) return FIDO_ERR_CBOR_TYPE;
  size_t required = 0;
  if (cbor_value_calculate_string_length(value, &required) != CborNoError)
    return FIDO_ERR_INVALID_CBOR;
  if (required > *size) return FIDO_ERR_INVALID_LENGTH;
  *size = required;
  return cbor_value_copy_byte_string(value, data, size, NULL) == CborNoError ?
      FIDO_OK : FIDO_ERR_INVALID_CBOR;
}

fido_status_t fido_cbor_text(const CborValue *value, char *data, size_t capacity) {
  if (!cbor_value_is_text_string(value)) return FIDO_ERR_CBOR_TYPE;
  size_t size = 0;
  if (cbor_value_calculate_string_length(value, &size) != CborNoError)
    return FIDO_ERR_INVALID_CBOR;
  if (size >= capacity) return FIDO_ERR_INVALID_LENGTH;
  size = capacity;
  if (cbor_value_copy_text_string(value, data, &size, NULL) != CborNoError)
    return FIDO_ERR_INVALID_CBOR;
  data[size] = '\0';
  // RP IDs and account names are C strings in the firmware; embedded NUL
  // must not turn a different RP into the same hash.
  return memchr(data, '\0', size) ? FIDO_ERR_INVALID_PARAMETER : FIDO_OK;
}

bool fido_cbor_equals(const CborValue *value, const char *text) {
  bool equal = false;
  return cbor_value_is_text_string(value) &&
      cbor_value_text_string_equals(value, text, &equal) == CborNoError && equal;
}

fido_status_t fido_cbor_option(const CborValue *map, const char *name,
                               bool fallback, bool *result) {
  CborValue value;
  *result = fallback;
  if (!fido_cbor_name(map, name, &value)) return FIDO_OK;
  if (!cbor_value_is_boolean(&value)) return FIDO_ERR_CBOR_TYPE;
  return cbor_value_get_boolean(&value, result) == CborNoError ?
      FIDO_OK : FIDO_ERR_INVALID_CBOR;
}
