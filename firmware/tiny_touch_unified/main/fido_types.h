#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define FIDO_MAX_MESSAGE 4096
#define FIDO_MAX_RESIDENT_CREDENTIALS 16
#define FIDO_CREDENTIAL_ID_SIZE 61
#define FIDO_USER_ID_MAX 64
#define FIDO_USER_NAME_MAX 64
#define FIDO_RESPONSE_MAX 1200

typedef enum {
  FIDO_CREDENTIAL_WRAPPED = 1,
  FIDO_CREDENTIAL_RESIDENT = 2,
} fido_credential_type_t;

typedef enum {
  FIDO_OK = 0,
  FIDO_ERR_INVALID_COMMAND = 0x01,
  FIDO_ERR_INVALID_PARAMETER = 0x02,
  FIDO_ERR_INVALID_LENGTH = 0x03,
  FIDO_ERR_CBOR_TYPE = 0x11,
  FIDO_ERR_INVALID_CBOR = 0x12,
  FIDO_ERR_MISSING_PARAMETER = 0x14,
  FIDO_ERR_CREDENTIAL_EXCLUDED = 0x19,
  FIDO_ERR_UNSUPPORTED_ALGORITHM = 0x26,
  FIDO_ERR_OPERATION_DENIED = 0x27,
  FIDO_ERR_KEY_STORE_FULL = 0x28,
  FIDO_ERR_UNSUPPORTED_OPTION = 0x2b,
  FIDO_ERR_INVALID_OPTION = 0x2c,
  FIDO_ERR_CANCELLED = 0x2d,
  FIDO_ERR_NO_CREDENTIALS = 0x2e,
  FIDO_ERR_USER_TIMEOUT = 0x2f,
  FIDO_ERR_NOT_ALLOWED = 0x30,
  FIDO_ERR_PIN_AUTH_INVALID = 0x33,
  FIDO_ERR_OTHER = 0x7f,
} fido_status_t;

typedef struct {
  uint8_t version;
  uint8_t master_key[32];
  uint32_t counter;
} fido_state_t;

typedef struct {
  uint8_t version;
  uint8_t user_id_length;
  uint8_t rp_hash[32];
  uint8_t credential_id[FIDO_CREDENTIAL_ID_SIZE];
  uint8_t user_id[FIDO_USER_ID_MAX];
  char user_name[FIDO_USER_NAME_MAX + 1];
  uint32_t created;
} fido_resident_t;

typedef enum {
  FIDO_STORAGE_OK,
  FIDO_STORAGE_NOT_FOUND,
  FIDO_STORAGE_ERROR,
} fido_storage_result_t;
