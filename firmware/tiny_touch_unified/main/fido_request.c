#include "fido_request.h"
#include "fido_crypto.h"
#include "fido_store.h"

#include <string.h>

static fido_status_t public_key_algorithm(const CborValue *array) {
  if (!cbor_value_is_array(array)) return FIDO_ERR_CBOR_TYPE;
  CborValue entry;
  FIDO_CBOR_TRY(cbor_value_enter_container(array, &entry));
  bool supported = false;
  while (!cbor_value_at_end(&entry)) {
    if (!cbor_value_is_map(&entry)) return FIDO_ERR_CBOR_TYPE;
    CborValue type, algorithm;
    if (!fido_cbor_name(&entry, "type", &type) ||
        !fido_cbor_name(&entry, "alg", &algorithm)) return FIDO_ERR_MISSING_PARAMETER;
    if (!cbor_value_is_text_string(&type) || !cbor_value_is_integer(&algorithm))
      return FIDO_ERR_CBOR_TYPE;
    int64_t number;
    if (cbor_value_get_int64_checked(&algorithm, &number) != CborNoError)
      return FIDO_ERR_INVALID_CBOR;
    supported |= fido_cbor_equals(&type, "public-key") && number == -7;
    FIDO_CBOR_TRY(cbor_value_advance(&entry));
  }
  return supported ? FIDO_OK : FIDO_ERR_UNSUPPORTED_ALGORITHM;
}

static fido_status_t request_options(const CborValue *map, bool creating,
                                      fido_request_t *request) {
  request->presence = true;
  CborValue options, value;
  if (fido_cbor_key(map, creating ? 7 : 5, &options)) {
    if (!cbor_value_is_map(&options)) return FIDO_ERR_CBOR_TYPE;
    FIDO_TRY(fido_cbor_option(&options, "rk", false, &request->resident));
    FIDO_TRY(fido_cbor_option(&options, "uv", false, &request->verification));
    FIDO_TRY(fido_cbor_option(&options, "up", true, &request->presence));
    if (fido_cbor_name(&options, creating ? "up" : "rk", &value))
      return FIDO_ERR_INVALID_OPTION;
    // Every option, including unknown ones, must be a boolean.
    CborValue entry;
    FIDO_CBOR_TRY(cbor_value_enter_container(&options, &entry));
    while (!cbor_value_at_end(&entry)) {
      if (!cbor_value_is_text_string(&entry)) return FIDO_ERR_CBOR_TYPE;
      FIDO_CBOR_TRY(cbor_value_advance(&entry));
      if (!cbor_value_is_boolean(&entry)) return FIDO_ERR_CBOR_TYPE;
      FIDO_CBOR_TRY(cbor_value_advance(&entry));
    }
  }
  if (fido_cbor_key(map, creating ? 6 : 4, &value) && !cbor_value_is_map(&value))
    return FIDO_ERR_CBOR_TYPE;
  // PIN protocols and extensions are not advertised. Do not treat a PIN
  // token as biometric verification or implement an unknown extension.
  if (fido_cbor_key(map, creating ? 8 : 6, &value)) {
    if (!cbor_value_is_byte_string(&value)) return FIDO_ERR_CBOR_TYPE;
    return FIDO_ERR_PIN_AUTH_INVALID;
  }
  if (fido_cbor_key(map, creating ? 9 : 7, &value)) {
    if (!cbor_value_is_unsigned_integer(&value)) return FIDO_ERR_CBOR_TYPE;
    return FIDO_ERR_PIN_AUTH_INVALID;
  }
  return FIDO_OK;
}

fido_status_t fido_request_parse(const CborValue *map, bool creating,
                                  fido_request_t *request) {
  memset(request, 0, sizeof(*request));
  CborValue challenge, rp, value;
  if (!fido_cbor_key(map, creating ? 1 : 2, &challenge) ||
      !fido_cbor_key(map, creating ? 2 : 1, &rp)) return FIDO_ERR_MISSING_PARAMETER;
  size_t size = sizeof(request->challenge);
  FIDO_TRY(fido_cbor_bytes(&challenge, request->challenge, &size));
  if (size != sizeof(request->challenge)) return FIDO_ERR_INVALID_LENGTH;
  if (creating) {
    if (!cbor_value_is_map(&rp)) return FIDO_ERR_CBOR_TYPE;
    if (!fido_cbor_name(&rp, "id", &value)) return FIDO_ERR_MISSING_PARAMETER;
    rp = value;
  }
  char rp_id[254];
  FIDO_TRY(fido_cbor_text(&rp, rp_id, sizeof(rp_id)));
  if (!rp_id[0]) return FIDO_ERR_INVALID_PARAMETER;
  if (!fido_crypto_sha256(rp_id, strlen(rp_id), request->rp_hash)) return FIDO_ERR_OTHER;
  if (creating) {
    CborValue user, algorithms;
    if (!fido_cbor_key(map, 3, &user) || !fido_cbor_key(map, 4, &algorithms))
      return FIDO_ERR_MISSING_PARAMETER;
    if (!cbor_value_is_map(&user)) return FIDO_ERR_CBOR_TYPE;
    if (!fido_cbor_name(&user, "id", &value)) return FIDO_ERR_MISSING_PARAMETER;
    request->user_id_size = sizeof(request->user_id);
    FIDO_TRY(fido_cbor_bytes(&value, request->user_id, &request->user_id_size));
    if (!request->user_id_size) return FIDO_ERR_INVALID_LENGTH;
    if (fido_cbor_name(&user, "name", &value))
      FIDO_TRY(fido_cbor_text(&value, request->user_name, sizeof(request->user_name)));
    FIDO_TRY(public_key_algorithm(&algorithms));
  }
  return request_options(map, creating, request);
}

static bool credential_available(const uint8_t id[FIDO_CREDENTIAL_ID_SIZE]) {
  if (id[0] == FIDO_CREDENTIAL_WRAPPED) return true;
  if (id[0] != FIDO_CREDENTIAL_RESIDENT) return false;
  // Resident handles remain valid only while their credential source exists.
  // The type byte is authenticated, so changing it cannot resurrect a replaced key.
  for (size_t i = 0; i < FIDO_MAX_RESIDENT_CREDENTIALS; i++) {
    const fido_resident_t *record = fido_store_resident(i);
    if (record && memcmp(record->credential_id, id, FIDO_CREDENTIAL_ID_SIZE) == 0)
      return true;
  }
  return false;
}

fido_status_t fido_request_credential(const CborValue *list,
                                      const uint8_t rp_hash[32], uint8_t id[61],
                                      bool *found) {
  *found = false;
  if (!cbor_value_is_array(list)) return FIDO_ERR_CBOR_TYPE;
  CborValue entry;
  FIDO_CBOR_TRY(cbor_value_enter_container(list, &entry));
  while (!cbor_value_at_end(&entry)) {
    if (!cbor_value_is_map(&entry)) return FIDO_ERR_CBOR_TYPE;
    CborValue type, credential;
    if (!fido_cbor_name(&entry, "type", &type) ||
        !fido_cbor_name(&entry, "id", &credential)) return FIDO_ERR_MISSING_PARAMETER;
    if (!cbor_value_is_text_string(&type) || !cbor_value_is_byte_string(&credential))
      return FIDO_ERR_CBOR_TYPE;
    size_t size = 0;
    FIDO_CBOR_TRY(cbor_value_calculate_string_length(&credential, &size));
    if (size == FIDO_CREDENTIAL_ID_SIZE && fido_cbor_equals(&type, "public-key")) {
      uint8_t candidate[FIDO_CREDENTIAL_ID_SIZE], private_key[32];
      FIDO_TRY(fido_cbor_bytes(&credential, candidate, &size));
      if (credential_available(candidate) &&
          fido_crypto_unwrap(fido_store_state(), rp_hash, candidate, private_key) && !*found) {
        memcpy(id, candidate, sizeof(candidate));
        *found = true;
      }
      fido_crypto_wipe(private_key, sizeof(private_key));
    }
    FIDO_CBOR_TRY(cbor_value_advance(&entry));
  }
  return FIDO_OK;
}
