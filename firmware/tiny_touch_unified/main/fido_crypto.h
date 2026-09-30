#pragma once

#include "fido_types.h"

bool fido_crypto_init(void);
bool fido_crypto_random(uint8_t *data, size_t size);
bool fido_crypto_sha256(const void *data, size_t size, uint8_t digest[32]);
bool fido_crypto_keypair(uint8_t private_key[32], uint8_t public_key[64]);
bool fido_crypto_sign(const uint8_t private_key[32], const uint8_t digest[32],
                      uint8_t signature[72], size_t *signature_size);
bool fido_crypto_wrap(const fido_state_t *state, const uint8_t rp_hash[32],
                      const uint8_t private_key[32], fido_credential_type_t type,
                      uint8_t id[FIDO_CREDENTIAL_ID_SIZE]);
bool fido_crypto_unwrap(const fido_state_t *state, const uint8_t rp_hash[32],
                        const uint8_t id[FIDO_CREDENTIAL_ID_SIZE], uint8_t private_key[32]);
void fido_crypto_wipe(void *data, size_t size);
