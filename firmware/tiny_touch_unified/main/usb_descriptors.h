#pragma once

#include <stdint.h>

#include "tusb.h"

extern tusb_desc_device_t const tiny_touch_device_descriptor;
extern uint8_t const tiny_touch_configuration_descriptor[];
extern uint8_t const tiny_touch_hid_report_descriptor[];
extern uint8_t const tiny_touch_fido_report_descriptor[];

#define TINYTOUCH_KEYBOARD_HID_INSTANCE 0
#define TINYTOUCH_FIDO_HID_INSTANCE 1
extern char const *tiny_touch_string_descriptors[];
extern int const tiny_touch_string_descriptor_count;

void tiny_touch_init_serial(void);
