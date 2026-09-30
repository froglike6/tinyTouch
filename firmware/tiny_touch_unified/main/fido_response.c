#include "fido_response.h"
#include "fido_crypto.h"
#include "fido_platform.h"
#include "fido_store.h"

#include <string.h>

static void auth_header(uint8_t *data, const uint8_t rp_hash[32],
                          uint8_t flags, uint32_t counter) {
  memcpy(data, rp_hash, 32);
  data[32] = flags;
  data[33] = (uint8_t)(counter >> 24);
  data[34] = (uint8_t)(counter >> 16);
  data[35] = (uint8_t)(counter >> 8);
  data[36] = (uint8_t)counter;
}

static bool sign_auth_data(const uint8_t private_key[32], const uint8_t *auth_data,
                            size_t auth_size, const uint8_t challenge[32],
                            uint8_t signature[72], size_t *signature_size) {
  uint8_t message[288], digest[32];
  if (auth_size > sizeof(message) - 32) return false;
  memcpy(message, auth_data, auth_size);
  memcpy(message + auth_size, challenge, 32);
  return fido_crypto_sha256(message, auth_size + 32, digest) &&
      !fido_platform_cancelled() &&
      fido_crypto_sign(private_key, digest, signature, signature_size);
}

static fido_status_t cose_public_key(const uint8_t key[64], uint8_t *data, size_t *size) {
  CborEncoder encoder, map;
  cbor_encoder_init(&encoder, data, *size, 0);
  FIDO_CBOR_TRY(cbor_encoder_create_map(&encoder, &map, 5));
  FIDO_CBOR_TRY(cbor_encode_int(&map, 1));
  FIDO_CBOR_TRY(cbor_encode_int(&map, 2));
  FIDO_CBOR_TRY(cbor_encode_int(&map, 3));
  FIDO_CBOR_TRY(cbor_encode_int(&map, -7));
  FIDO_CBOR_TRY(cbor_encode_int(&map, -1));
  FIDO_CBOR_TRY(cbor_encode_int(&map, 1));
  FIDO_CBOR_TRY(cbor_encode_int(&map, -2));
  FIDO_CBOR_TRY(cbor_encode_byte_string(&map, key, 32));
  FIDO_CBOR_TRY(cbor_encode_int(&map, -3));
  FIDO_CBOR_TRY(cbor_encode_byte_string(&map, key + 32, 32));
  FIDO_CBOR_TRY(cbor_encoder_close_container(&encoder, &map));
  *size = cbor_encoder_get_buffer_size(&encoder, data);
  return FIDO_OK;
}

static fido_status_t make_response(const uint8_t *auth, size_t auth_size,
                                    const uint8_t *signature, size_t signature_size,
                                    uint8_t *response, size_t *size) {
  CborEncoder encoder, map, statement;
  cbor_encoder_init(&encoder, response, *size, 0);
  FIDO_CBOR_TRY(cbor_encoder_create_map(&encoder, &map, 3));
  FIDO_CBOR_TRY(cbor_encode_int(&map, 1));
  FIDO_CBOR_TRY(cbor_encode_text_stringz(&map, "packed"));
  FIDO_CBOR_TRY(cbor_encode_int(&map, 2));
  FIDO_CBOR_TRY(cbor_encode_byte_string(&map, auth, auth_size));
  FIDO_CBOR_TRY(cbor_encode_int(&map, 3));
  FIDO_CBOR_TRY(cbor_encoder_create_map(&map, &statement, 2));
  FIDO_CBOR_TRY(cbor_encode_text_stringz(&statement, "alg"));
  FIDO_CBOR_TRY(cbor_encode_int(&statement, -7));
  FIDO_CBOR_TRY(cbor_encode_text_stringz(&statement, "sig"));
  FIDO_CBOR_TRY(cbor_encode_byte_string(&statement, signature, signature_size));
  FIDO_CBOR_TRY(cbor_encoder_close_container(&map, &statement));
  FIDO_CBOR_TRY(cbor_encoder_close_container(&encoder, &map));
  *size = cbor_encoder_get_buffer_size(&encoder, response);
  return FIDO_OK;
}

fido_status_t fido_response_make(const fido_request_t *request,
                                  uint8_t *response, size_t *size) {
  int slot = request->resident ? fido_store_resident_slot(request->rp_hash,
      request->user_id, request->user_id_size) : -1;
  if (request->resident && slot < 0) return FIDO_ERR_KEY_STORE_FULL;
  uint8_t private_key[32], public_key[64], auth[256], signature[72];
  fido_resident_t record = {.version = 1};
  size_t signature_size = 0, cose_size = sizeof(auth) - 55 - FIDO_CREDENTIAL_ID_SIZE;
  uint32_t counter = 0;
  bool ok = !fido_platform_cancelled() && fido_crypto_keypair(private_key, public_key) &&
      fido_crypto_wrap(fido_store_state(), request->rp_hash, private_key,
                       request->resident ? FIDO_CREDENTIAL_RESIDENT : FIDO_CREDENTIAL_WRAPPED,
                       record.credential_id) &&
      cose_public_key(public_key, auth + 55 + FIDO_CREDENTIAL_ID_SIZE, &cose_size) == FIDO_OK &&
      fido_store_next_counter(&counter);
  size_t auth_size = 55 + FIDO_CREDENTIAL_ID_SIZE + cose_size;
  if (ok) {
    auth_header(auth, request->rp_hash, 0x45, counter); // UP, UV, AT
    memset(auth + 37, 0, 16); // No assigned AAGUID or manufacturer attestation.
    auth[53] = 0;
    auth[54] = FIDO_CREDENTIAL_ID_SIZE;
    memcpy(auth + 55, record.credential_id, FIDO_CREDENTIAL_ID_SIZE);
    ok = sign_auth_data(private_key, auth, auth_size, request->challenge,
                        signature, &signature_size);
  }
  fido_crypto_wipe(private_key, sizeof(private_key));
  if (ok && request->resident) {
    memcpy(record.rp_hash, request->rp_hash, 32);
    memcpy(record.user_id, request->user_id, request->user_id_size);
    record.user_id_length = (uint8_t)request->user_id_size;
    memcpy(record.user_name, request->user_name, sizeof(record.user_name));
    record.created = counter;
    ok = fido_store_save_resident((size_t)slot, &record);
  }
  fido_crypto_wipe(&record, sizeof(record));
  if (fido_platform_cancelled()) return FIDO_ERR_CANCELLED;
  return ok ? make_response(auth, auth_size, signature, signature_size, response, size) :
      FIDO_ERR_OTHER;
}

fido_status_t fido_response_assert(const fido_request_t *request,
                                    const uint8_t id[FIDO_CREDENTIAL_ID_SIZE],
                                    const fido_resident_t *resident,
                                    uint8_t flags, size_t count,
                                    uint8_t *response, size_t *size) {
  uint8_t private_key[32], auth[37], signature[72];
  size_t signature_size = 0;
  uint32_t counter = 0;
  bool ok = fido_crypto_unwrap(fido_store_state(), request->rp_hash, id, private_key) &&
      fido_store_next_counter(&counter);
  if (ok) {
    auth_header(auth, request->rp_hash, flags, counter);
    ok = sign_auth_data(private_key, auth, sizeof(auth), request->challenge,
                        signature, &signature_size);
  }
  fido_crypto_wipe(private_key, sizeof(private_key));
  if (fido_platform_cancelled()) return FIDO_ERR_CANCELLED;
  if (!ok) return FIDO_ERR_OTHER;
  CborEncoder encoder, map, credential, user;
  cbor_encoder_init(&encoder, response, *size, 0);
  FIDO_CBOR_TRY(cbor_encoder_create_map(&encoder, &map, 3 + (resident != NULL) + (count > 1)));
  FIDO_CBOR_TRY(cbor_encode_int(&map, 1));
  FIDO_CBOR_TRY(cbor_encoder_create_map(&map, &credential, 2));
  FIDO_CBOR_TRY(cbor_encode_text_stringz(&credential, "id"));
  FIDO_CBOR_TRY(cbor_encode_byte_string(&credential, id, FIDO_CREDENTIAL_ID_SIZE));
  FIDO_CBOR_TRY(cbor_encode_text_stringz(&credential, "type"));
  FIDO_CBOR_TRY(cbor_encode_text_stringz(&credential, "public-key"));
  FIDO_CBOR_TRY(cbor_encoder_close_container(&map, &credential));
  FIDO_CBOR_TRY(cbor_encode_int(&map, 2));
  FIDO_CBOR_TRY(cbor_encode_byte_string(&map, auth, sizeof(auth)));
  FIDO_CBOR_TRY(cbor_encode_int(&map, 3));
  FIDO_CBOR_TRY(cbor_encode_byte_string(&map, signature, signature_size));
  if (resident) {
    bool name = (flags & 0x04) && resident->user_name[0];
    FIDO_CBOR_TRY(cbor_encode_int(&map, 4));
    FIDO_CBOR_TRY(cbor_encoder_create_map(&map, &user, 1 + name));
    FIDO_CBOR_TRY(cbor_encode_text_stringz(&user, "id"));
    FIDO_CBOR_TRY(cbor_encode_byte_string(&user, resident->user_id, resident->user_id_length));
    if (name) {
      FIDO_CBOR_TRY(cbor_encode_text_stringz(&user, "name"));
      FIDO_CBOR_TRY(cbor_encode_text_stringz(&user, resident->user_name));
    }
    FIDO_CBOR_TRY(cbor_encoder_close_container(&map, &user));
  }
  if (count > 1) {
    FIDO_CBOR_TRY(cbor_encode_int(&map, 5));
    FIDO_CBOR_TRY(cbor_encode_uint(&map, count));
  }
  FIDO_CBOR_TRY(cbor_encoder_close_container(&encoder, &map));
  *size = cbor_encoder_get_buffer_size(&encoder, response);
  return FIDO_OK;
}

fido_status_t fido_response_info(uint8_t *response, size_t *size) {
  CborEncoder encoder, map, versions, options;
  uint8_t aaguid[16] = {0};
  cbor_encoder_init(&encoder, response, *size, 0);
  FIDO_CBOR_TRY(cbor_encoder_create_map(&encoder, &map, 4));
  FIDO_CBOR_TRY(cbor_encode_int(&map, 1));
  FIDO_CBOR_TRY(cbor_encoder_create_array(&map, &versions, 1));
  FIDO_CBOR_TRY(cbor_encode_text_stringz(&versions, "FIDO_2_0"));
  FIDO_CBOR_TRY(cbor_encoder_close_container(&map, &versions));
  FIDO_CBOR_TRY(cbor_encode_int(&map, 3));
  FIDO_CBOR_TRY(cbor_encode_byte_string(&map, aaguid, sizeof(aaguid)));
  FIDO_CBOR_TRY(cbor_encode_int(&map, 4));
  FIDO_CBOR_TRY(cbor_encoder_create_map(&map, &options, 3));
  FIDO_CBOR_TRY(cbor_encode_text_stringz(&options, "rk"));
  FIDO_CBOR_TRY(cbor_encode_boolean(&options, true));
  FIDO_CBOR_TRY(cbor_encode_text_stringz(&options, "up"));
  FIDO_CBOR_TRY(cbor_encode_boolean(&options, true));
  FIDO_CBOR_TRY(cbor_encode_text_stringz(&options, "uv"));
  FIDO_CBOR_TRY(cbor_encode_boolean(&options, fido_platform_uv_configured()));
  FIDO_CBOR_TRY(cbor_encoder_close_container(&map, &options));
  FIDO_CBOR_TRY(cbor_encode_int(&map, 5));
  FIDO_CBOR_TRY(cbor_encode_uint(&map, FIDO_MAX_MESSAGE));
  FIDO_CBOR_TRY(cbor_encoder_close_container(&encoder, &map));
  *size = cbor_encoder_get_buffer_size(&encoder, response);
  return FIDO_OK;
}
