#pragma once

#include "fido_types.h"

// The authenticator worker serializes core and persistent-state operations.
bool fido_core_init(void);
bool fido_core_ready(void);
bool fido_core_reset(void);
void fido_core_invalidate(void);
size_t fido_core_resident_count(void);
size_t fido_core_request(uint32_t channel, const uint8_t *request,
                         size_t request_size, uint8_t response[FIDO_RESPONSE_MAX]);
