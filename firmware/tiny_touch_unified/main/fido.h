#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

void fido_start(int enrolled_fingers);
bool fido_ready(void);
bool fido_operation_active(void);
size_t fido_resident_count(void);
void fido_sensor_count_changed(int count);
void fido_receive_report(const uint8_t *data, size_t size);
bool fido_factory_reset(void);
