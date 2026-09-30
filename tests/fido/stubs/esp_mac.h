#pragma once
#include <stdint.h>
#define ESP_MAC_WIFI_STA 0
#define ESP_OK 0
static inline int esp_read_mac(uint8_t mac[6], int kind) {
  (void)kind;
  for (unsigned i = 0; i < 6; i++) mac[i] = (uint8_t)i;
  return 0;
}
