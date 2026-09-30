#include "fido_hid.h"

#include <string.h>

enum { HID_PING = 0x81, HID_INIT = 0x86, HID_CBOR = 0x90,
       HID_CANCEL = 0x91, HID_KEEPALIVE = 0xbb, HID_ERROR = 0xbf };
enum { HID_INVALID_COMMAND = 1, HID_INVALID_LENGTH = 3,
       HID_INVALID_SEQUENCE = 4, HID_TIMEOUT = 5, HID_BUSY = 6,
       HID_INVALID_CHANNEL = 0x0b };

static uint32_t read_channel(const uint8_t *data) {
  return ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16) |
      ((uint32_t)data[2] << 8) | data[3];
}

static void write_channel(uint8_t *data, uint32_t channel) {
  data[0] = (uint8_t)(channel >> 24);
  data[1] = (uint8_t)(channel >> 16);
  data[2] = (uint8_t)(channel >> 8);
  data[3] = (uint8_t)channel;
}

static void send_message(fido_hid_t *hid, uint32_t channel, uint8_t command,
                          const uint8_t *data, size_t size) {
  uint8_t report[64] = {0};
  write_channel(report, channel);
  report[4] = command;
  report[5] = (uint8_t)(size >> 8);
  report[6] = (uint8_t)size;
  size_t amount = size < 57 ? size : 57;
  if (amount) memcpy(report + 7, data, amount);
  if (!hid->callbacks.send(report)) return;
  size_t sent = amount;
  uint8_t sequence = 0;
  while (sent < size) {
    memset(report + 4, 0, 60);
    report[4] = sequence++;
    amount = size - sent < 59 ? size - sent : 59;
    memcpy(report + 5, data + sent, amount);
    if (!hid->callbacks.send(report)) return;
    sent += amount;
  }
}

static void send_error(fido_hid_t *hid, uint32_t channel, uint8_t error) {
  send_message(hid, channel, HID_ERROR, &error, 1);
}

static bool channel_known(const fido_hid_t *hid, uint32_t channel) {
  if (!channel || channel == FIDO_HID_BROADCAST) return false;
  for (size_t i = 0; i < FIDO_HID_CHANNELS; i++)
    if (hid->channels[i] == channel) return true;
  return false;
}

void fido_hid_init(fido_hid_t *hid, const fido_hid_callbacks_t *callbacks) {
  memset(hid, 0, sizeof(*hid));
  hid->callbacks = *callbacks;
  hid->next_channel = 1;
}

static void initialize_channel(fido_hid_t *hid, uint32_t channel, const uint8_t *nonce) {
  uint32_t assigned = channel;
  if (channel == FIDO_HID_BROADCAST) {
    do { assigned = hid->next_channel++; }
    while (!assigned || assigned == FIDO_HID_BROADCAST || channel_known(hid, assigned));
    size_t index = hid->channel_cursor++ % FIDO_HID_CHANNELS;
    if (hid->channels[index] == hid->active_channel)
      index = hid->channel_cursor++ % FIDO_HID_CHANNELS;
    hid->channels[index] = assigned;
  } else {
    if (hid->rx_channel == channel) hid->rx_channel = 0;
    if (hid->active && hid->active_channel == channel) {
      hid->callbacks.cancel(true);
      hid->active = false;
      hid->generation++;
    } else if (!hid->worker_busy) hid->callbacks.cancel(true);
  }
  uint8_t response[17];
  memcpy(response, nonce, 8);
  write_channel(response + 8, assigned);
  response[12] = 2; // CTAPHID protocol version
  response[13] = 0; response[14] = 2; response[15] = 0;
  response[16] = 0x0c; // CBOR supported; legacy CTAPHID_MSG unsupported.
  send_message(hid, channel, HID_INIT, response, sizeof(response));
}

static void dispatch_message(fido_hid_t *hid, uint32_t now) {
  uint32_t channel = hid->rx_channel;
  uint8_t command = hid->rx_command;
  size_t size = hid->rx_size;
  hid->rx_channel = 0;
  if (command == HID_PING) {
    send_message(hid, channel, command, hid->rx_data, size);
  } else if (command == HID_CBOR) {
    if (!size) { send_error(hid, channel, HID_INVALID_LENGTH); return; }
    hid->generation++;
    hid->active_channel = channel;
    hid->active = hid->worker_busy = true;
    hid->keepalive_time = now;
    if (!hid->callbacks.request(channel, hid->generation, hid->rx_data, size)) {
      hid->active = hid->worker_busy = false;
      send_error(hid, channel, HID_BUSY);
    }
  } else {
    send_error(hid, channel, HID_INVALID_COMMAND);
  }
}

void fido_hid_receive(fido_hid_t *hid, const uint8_t report[64], uint32_t now) {
  uint32_t channel = read_channel(report);
  uint8_t command = report[4];
  bool initial = (command & 0x80) != 0;
  if (!channel || (!channel_known(hid, channel) &&
      !(channel == FIDO_HID_BROADCAST && command == HID_INIT))) {
    send_error(hid, channel, HID_INVALID_CHANNEL);
    return;
  }
  if (initial && command == HID_INIT) {
    if (report[5] || report[6] != 8) send_error(hid, channel, HID_INVALID_LENGTH);
    else initialize_channel(hid, channel, report + 7);
    return;
  }
  if (initial && command == HID_CANCEL) {
    if (report[5] || report[6]) { send_error(hid, channel, HID_INVALID_LENGTH); return; }
    if (hid->active && hid->active_channel == channel) hid->callbacks.cancel(true);
    if (hid->rx_channel == channel) hid->rx_channel = 0;
    return;
  }
  if (hid->worker_busy || (hid->rx_channel && hid->rx_channel != channel)) {
    if (initial) send_error(hid, channel, HID_BUSY);
    return;
  }
  if (initial) {
    if (hid->rx_channel) {
      hid->rx_channel = 0;
      send_error(hid, channel, HID_INVALID_SEQUENCE);
      return;
    }
    size_t size = ((size_t)report[5] << 8) | report[6];
    if (size > FIDO_MAX_MESSAGE) { send_error(hid, channel, HID_INVALID_LENGTH); return; }
    if (command != HID_PING && command != HID_CBOR) {
      send_error(hid, channel, HID_INVALID_COMMAND); return;
    }
    hid->rx_channel = channel;
    hid->rx_command = command;
    hid->rx_size = size;
    hid->rx_received = size < 57 ? size : 57;
    hid->rx_sequence = 0;
    if (hid->rx_received) memcpy(hid->rx_data, report + 7, hid->rx_received);
  } else {
    if (!hid->rx_channel) return; // Stray continuation packets are ignored.
    if (command != hid->rx_sequence++) {
      hid->rx_channel = 0;
      send_error(hid, channel, HID_INVALID_SEQUENCE);
      return;
    }
    size_t amount = hid->rx_size - hid->rx_received;
    if (amount > 59) amount = 59;
    memcpy(hid->rx_data + hid->rx_received, report + 5, amount);
    hid->rx_received += amount;
  }
  hid->rx_time = now;
  if (hid->rx_received == hid->rx_size) dispatch_message(hid, now);
}

void fido_hid_tick(fido_hid_t *hid, uint32_t now, bool waiting_for_user) {
  if (hid->rx_channel && (uint32_t)(now - hid->rx_time) >= 500) {
    send_error(hid, hid->rx_channel, HID_TIMEOUT);
    hid->rx_channel = 0;
  }
  if (hid->active && (uint32_t)(now - hid->keepalive_time) >= 100) {
    uint8_t status = waiting_for_user ? 2 : 1;
    send_message(hid, hid->active_channel, HID_KEEPALIVE, &status, 1);
    hid->keepalive_time = now;
  }
}

void fido_hid_complete(fido_hid_t *hid, uint32_t generation,
                         const uint8_t *data, size_t size) {
  if (hid->active && hid->generation == generation)
    send_message(hid, hid->active_channel, HID_CBOR, data, size);
  hid->active = hid->worker_busy = false;
}

void fido_hid_disconnect(fido_hid_t *hid) {
  hid->callbacks.cancel(true);
  hid->rx_channel = 0;
  hid->active = false;
  hid->generation++;
  memset(hid->channels, 0, sizeof(hid->channels));
}
