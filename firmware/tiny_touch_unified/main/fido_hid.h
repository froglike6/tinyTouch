#pragma once

#include "fido_types.h"

#define FIDO_HID_REPORT_SIZE 64
#define FIDO_HID_BROADCAST UINT32_MAX
#define FIDO_HID_CHANNELS 8

typedef struct {
  bool (*send)(const uint8_t report[FIDO_HID_REPORT_SIZE]);
  bool (*request)(uint32_t channel, uint32_t generation, const uint8_t *data, size_t size);
  void (*cancel)(bool invalidate);
} fido_hid_callbacks_t;

typedef struct {
  fido_hid_callbacks_t callbacks;
  uint32_t channels[FIDO_HID_CHANNELS];
  uint32_t next_channel;
  size_t channel_cursor;
  uint32_t rx_channel;
  uint32_t rx_time;
  uint8_t rx_command;
  uint8_t rx_sequence;
  size_t rx_size;
  size_t rx_received;
  uint8_t rx_data[FIDO_MAX_MESSAGE];
  bool worker_busy;
  bool active;
  uint32_t active_channel;
  uint32_t generation;
  uint32_t keepalive_time;
} fido_hid_t;

void fido_hid_init(fido_hid_t *hid, const fido_hid_callbacks_t *callbacks);
void fido_hid_receive(fido_hid_t *hid, const uint8_t report[64], uint32_t now);
void fido_hid_tick(fido_hid_t *hid, uint32_t now, bool waiting_for_user);
void fido_hid_complete(fido_hid_t *hid, uint32_t generation,
                         const uint8_t *data, size_t size);
void fido_hid_disconnect(fido_hid_t *hid);
