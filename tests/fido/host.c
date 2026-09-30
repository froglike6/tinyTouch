// Only storage, time, USB I/O and physical biometrics are substituted. The
// authenticator, CTAPHID, CBOR and cryptography are the production C sources.
#include "fido_core.h"
#include "fido_hid.h"
#include "fido_platform.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char *storage_path;
static uint32_t now, uv_checks;
static bool user_configured = true, cancelled, fail_write, invalidated;
static bool fail_entropy;
static fido_status_t verification = FIDO_OK;
static fido_hid_t hid;
static struct {
  bool pending;
  uint32_t channel, generation;
  size_t size;
  uint8_t data[FIDO_MAX_MESSAGE];
} job;

static bool path_for(char path[1024], const char *key) {
  int size = snprintf(path, 1024, "%s/%s", storage_path, key);
  return size > 0 && size < 1024;
}

fido_storage_result_t fido_platform_read(const char *key, void *data, size_t *size) {
  char path[1024];
  if (!path_for(path, key)) return FIDO_STORAGE_ERROR;
  FILE *file = fopen(path, "rb");
  if (!file) return errno == ENOENT ? FIDO_STORAGE_NOT_FOUND : FIDO_STORAGE_ERROR;
  size_t read = fread(data, 1, *size, file);
  bool ok = !ferror(file) && fgetc(file) == EOF;
  fclose(file);
  *size = read;
  return ok ? FIDO_STORAGE_OK : FIDO_STORAGE_ERROR;
}

bool fido_platform_write(const char *key, const void *data, size_t size) {
  if (fail_write) return false;
  char path[1024], temporary[1030];
  if (!path_for(path, key)) return false;
  snprintf(temporary, sizeof(temporary), "%s.new", path);
  FILE *file = fopen(temporary, "wb");
  if (!file) return false;
  bool ok = fwrite(data, 1, size, file) == size;
  if (fclose(file) != 0) ok = false;
  return ok && rename(temporary, path) == 0;
}

bool fido_platform_erase(void) {
  if (fail_write) return false;
  char path[1024];
  if (!path_for(path, "state")) return false;
  if (unlink(path) != 0 && errno != ENOENT) return false;
  for (size_t i = 0; i < FIDO_MAX_RESIDENT_CREDENTIALS; i++) {
    char key[8];
    snprintf(key, sizeof(key), "rk%02u", (unsigned)i);
    if (!path_for(path, key) || (unlink(path) != 0 && errno != ENOENT)) return false;
  }
  return true;
}

int fido_platform_entropy(void *context, uint8_t *data, size_t size) {
  (void)context;
  if (fail_entropy) return -1;
  FILE *file = fopen("/dev/urandom", "rb");
  if (!file) return -1;
  bool ok = fread(data, 1, size, file) == size;
  fclose(file);
  return ok ? 0 : -1;
}

uint32_t fido_platform_time_ms(void) { return now; }
bool fido_platform_uv_configured(void) { return user_configured; }
bool fido_platform_cancelled(void) { return cancelled; }
fido_status_t fido_platform_verify_user(void) {
  uv_checks++;
  return cancelled ? FIDO_ERR_CANCELLED : verification;
}

static void print_bytes(const uint8_t *data, size_t size) {
  for (size_t i = 0; i < size; i++) printf("%02x", data[i]);
  putchar('\n');
}

static bool send_report(const uint8_t data[64]) { print_bytes(data, 64); return true; }

static bool start_request(uint32_t channel, uint32_t generation,
                            const uint8_t *data, size_t size) {
  if (job.pending) return false;
  job.pending = true;
  job.channel = channel;
  job.generation = generation;
  job.size = size;
  memcpy(job.data, data, size);
  cancelled = false;
  return true;
}

static void cancel_request(bool invalidate) {
  cancelled = true;
  invalidated |= invalidate;
}

static bool parse_hex(const char *text, uint8_t *data, size_t capacity, size_t *size) {
  size_t length = strcspn(text, "\r\n ");
  if ((length % 2) || length / 2 > capacity) return false;
  *size = length / 2;
  for (size_t i = 0; i < *size; i++) {
    unsigned number;
    if (sscanf(text + i * 2, "%2x", &number) != 1) return false;
    data[i] = (uint8_t)number;
  }
  return true;
}

int main(int argc, char **argv) {
  if (argc != 2) return 2;
  storage_path = argv[1];
  (void)fido_core_init();
  const fido_hid_callbacks_t callbacks = {
    .send = send_report, .request = start_request, .cancel = cancel_request,
  };
  fido_hid_init(&hid, &callbacks);
  char line[FIDO_MAX_MESSAGE * 2 + 64];
  uint8_t data[FIDO_MAX_MESSAGE], response[FIDO_RESPONSE_MAX];
  while (fgets(line, sizeof(line), stdin)) {
    size_t size = 0;
    unsigned value = 0;
    switch (line[0]) {
      case 'R':
        if (!parse_hex(line + 2, data, sizeof(data), &size) || size != 64) return 3;
        fido_hid_receive(&hid, data, now);
        break;
      case 'P':
        if (job.pending) {
          if (invalidated) { fido_core_invalidate(); invalidated = false; }
          size = fido_core_request(job.channel, job.data, job.size, response);
          fido_hid_complete(&hid, job.generation, response, size);
          job.pending = false;
        }
        break;
      case 'C':
        if (sscanf(line + 2, "%x", &value) != 1) return 3;
        {
          const char *payload = strchr(line + 2, ' ');
          if (!payload || !parse_hex(payload + 1, data, sizeof(data), &size)) return 3;
          cancelled = false;
          size = fido_core_request(value, data, size, response);
          print_bytes(response, size);
        }
        break;
      case 'T':
        if (sscanf(line + 2, "%u", &value) != 1) return 3;
        now = value;
        fido_hid_tick(&hid, now, true);
        break;
      case 'U':
        if (sscanf(line + 2, "%u", &value) != 1) return 3;
        verification = (fido_status_t)value;
        break;
      case 'V': user_configured = line[2] == '1'; break;
      case 'F': fail_write = line[2] == '1'; break;
      case 'E': fail_entropy = line[2] == '1'; break;
      case 'I': (void)fido_core_init(); break;
      case 'Z': (void)fido_core_reset(); break;
      case 'D': fido_hid_disconnect(&hid); break;
      case 'Q':
        printf("%08x%08x\n", uv_checks, (unsigned)fido_core_resident_count());
        break;
      default: return 3;
    }
    puts("END");
    fflush(stdout);
  }
  return 0;
}
