#pragma once

#include "fido_types.h"

// Storage is a dedicated partition; PIV and configuration never use it.
fido_storage_result_t fido_platform_read(const char *key, void *data, size_t *size);
bool fido_platform_write(const char *key, const void *data, size_t size);
bool fido_platform_erase(void);
int fido_platform_entropy(void *context, uint8_t *data, size_t size);
uint32_t fido_platform_time_ms(void);
bool fido_platform_uv_configured(void);
bool fido_platform_cancelled(void);
fido_status_t fido_platform_verify_user(void);
