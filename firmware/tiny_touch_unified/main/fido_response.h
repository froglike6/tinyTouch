#pragma once

#include "fido_request.h"

fido_status_t fido_response_make(const fido_request_t *request,
                                  uint8_t *response, size_t *size);
fido_status_t fido_response_assert(const fido_request_t *request,
                                    const uint8_t id[FIDO_CREDENTIAL_ID_SIZE],
                                    const fido_resident_t *resident,
                                    uint8_t flags, size_t count,
                                    uint8_t *response, size_t *size);
fido_status_t fido_response_info(uint8_t *response, size_t *size);
