#include "fido_crypto.h"
#include "fido_platform.h"

#include <string.h>

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/gcm.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/sha256.h"

static mbedtls_ctr_drbg_context drbg;
static bool drbg_initialized;
static bool drbg_seeded;

void fido_crypto_wipe(void *data, size_t size) {
  mbedtls_platform_zeroize(data, size);
}

bool fido_crypto_init(void) {
  static const uint8_t personalization[] = "tinyTouch FIDO2";
  if (drbg_initialized) mbedtls_ctr_drbg_free(&drbg);
  mbedtls_ctr_drbg_init(&drbg);
  drbg_initialized = true;
  drbg_seeded = mbedtls_ctr_drbg_seed(&drbg, fido_platform_entropy, NULL,
                                     personalization, sizeof(personalization) - 1) == 0;
  return drbg_seeded;
}

bool fido_crypto_random(uint8_t *data, size_t size) {
  return drbg_seeded && mbedtls_ctr_drbg_random(&drbg, data, size) == 0;
}

bool fido_crypto_sha256(const void *data, size_t size, uint8_t digest[32]) {
  return mbedtls_sha256(data, size, digest, 0) == 0;
}

bool fido_crypto_keypair(uint8_t private_key[32], uint8_t public_key[64]) {
  if (!drbg_seeded) { fido_crypto_wipe(private_key, 32); return false; }
  mbedtls_ecp_keypair key;
  mbedtls_ecp_keypair_init(&key);
  uint8_t point[65];
  size_t point_size = 0;
  size_t private_size = 0;
  int result = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, &key,
                                  mbedtls_ctr_drbg_random, &drbg);
  if (result == 0) result = mbedtls_ecp_write_key_ext(&key, &private_size, private_key, 32);
  if (result == 0 && private_size != 32) result = -1;
  if (result == 0) {
    result = mbedtls_ecp_point_write_binary(&key.MBEDTLS_PRIVATE(grp),
        &key.MBEDTLS_PRIVATE(Q), MBEDTLS_ECP_PF_UNCOMPRESSED,
        &point_size, point, sizeof(point));
  }
  if (result == 0 && point_size == sizeof(point)) memcpy(public_key, point + 1, 64);
  else result = -1;
  mbedtls_ecp_keypair_free(&key);
  if (result != 0) fido_crypto_wipe(private_key, 32);
  return result == 0;
}

bool fido_crypto_sign(const uint8_t private_key[32], const uint8_t digest[32],
                      uint8_t signature[72], size_t *signature_size) {
  if (!drbg_seeded) return false;
  mbedtls_ecp_keypair key;
  mbedtls_ecdsa_context signer;
  mbedtls_ecp_keypair_init(&key);
  mbedtls_ecdsa_init(&signer);
  int result = mbedtls_ecp_read_key(MBEDTLS_ECP_DP_SECP256R1, &key, private_key, 32);
  if (result == 0) result = mbedtls_ecdsa_from_keypair(&signer, &key);
  if (result == 0) {
    result = mbedtls_ecdsa_write_signature(&signer, MBEDTLS_MD_SHA256,
        digest, 32, signature, 72, signature_size, mbedtls_ctr_drbg_random, &drbg);
  }
  mbedtls_ecdsa_free(&signer);
  mbedtls_ecp_keypair_free(&key);
  return result == 0;
}

bool fido_crypto_wrap(const fido_state_t *state, const uint8_t rp_hash[32],
                      const uint8_t private_key[32], fido_credential_type_t type,
                      uint8_t id[FIDO_CREDENTIAL_ID_SIZE]) {
  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);
  id[0] = (uint8_t)type;
  uint8_t aad[33] = {id[0]};
  memcpy(aad + 1, rp_hash, 32);
  bool ok = fido_crypto_random(id + 1, 12) &&
      mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, state->master_key, 256) == 0 &&
      mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, 32, id + 1, 12,
                               aad, sizeof(aad), private_key, id + 13, 16, id + 45) == 0;
  mbedtls_gcm_free(&gcm);
  return ok;
}

bool fido_crypto_unwrap(const fido_state_t *state, const uint8_t rp_hash[32],
                        const uint8_t id[FIDO_CREDENTIAL_ID_SIZE], uint8_t private_key[32]) {
  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);
  uint8_t aad[33] = {id[0]};
  memcpy(aad + 1, rp_hash, 32);
  bool ok = (id[0] == FIDO_CREDENTIAL_WRAPPED || id[0] == FIDO_CREDENTIAL_RESIDENT) &&
      mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, state->master_key, 256) == 0 &&
      mbedtls_gcm_auth_decrypt(&gcm, 32, id + 1, 12, aad, sizeof(aad),
                              id + 45, 16, id + 13, private_key) == 0;
  mbedtls_gcm_free(&gcm);
  if (!ok) fido_crypto_wipe(private_key, 32);
  return ok;
}
