#include "usb_descriptors.h"

#include <assert.h>
#include <stdbool.h>
#include <string.h>

int main(void) {
  const uint8_t *config = tiny_touch_configuration_descriptor;
  size_t length = config[2] | ((size_t)config[3] << 8);
  assert(config[4] == 5 && tiny_touch_device_descriptor.bNumConfigurations == 1);
  bool endpoints[256] = {0}, interfaces[5] = {0};
  unsigned in_count = 1, interface = 0, described = 0, actual = 0;
  size_t fido_report_size = 0;
  unsigned fido_in = 0, fido_out = 0;
  for (size_t offset = 9; offset < length; offset += config[offset]) {
    const uint8_t *desc = config + offset;
    assert(desc[0] >= 2 && offset + desc[0] <= length);
    if (desc[1] == TUSB_DESC_INTERFACE) {
      if (interfaces[interface]) assert(actual == described);
      interface = desc[2];
      assert(interface < 5 && !interfaces[interface] && desc[3] == 0);
      interfaces[interface] = true;
      described = desc[4]; actual = 0;
      if (interface == 0) assert(desc[5] == 0x0b && described == 2);
      if (interface == 1) assert(desc[5] == TUSB_CLASS_HID && desc[7] == 1);
      if (interface == 2) assert(desc[5] == TUSB_CLASS_CDC && described == 0);
      if (interface == 3) assert(desc[5] == TUSB_CLASS_CDC_DATA && described == 2);
      if (interface == 4) assert(desc[5] == TUSB_CLASS_HID && desc[7] == 0 && described == 2);
    } else if (desc[1] == TUSB_DESC_ENDPOINT) {
      uint8_t address = desc[2];
      assert(!endpoints[address] && (address & 15) > 0 && (address & 15) < 7);
      endpoints[address] = true;
      actual++;
      if (address & 0x80) {
        // The ESP32-S3 DWC2 backend maps IN endpoint numbers to TX FIFOs 1-4.
        assert((address & 15) <= 4);
        in_count++;
      }
      if (interface == 4) {
        assert((desc[3] & 3) == TUSB_XFER_INTERRUPT && desc[4] == 64);
        if (address & 0x80) fido_in++;
        else fido_out++;
      }
    } else if (desc[1] == HID_DESC_TYPE_HID && interface == 4) {
      fido_report_size = desc[7] | ((size_t)desc[8] << 8);
    }
  }
  assert(actual == described && in_count == 5);
  for (unsigned i = 0; i < 5; i++) assert(interfaces[i]);
  assert(endpoints[0x01] && endpoints[0x81] && endpoints[0x82]);
  assert(endpoints[0x04] && endpoints[0x84]);
  assert(fido_in == 1 && fido_out == 1 && fido_report_size > 0);
  const uint8_t usage_page[] = {0x06, 0xd0, 0xf1};
  assert(memcmp(tiny_touch_fido_report_descriptor, usage_page, sizeof(usage_page)) == 0);
  return 0;
}
