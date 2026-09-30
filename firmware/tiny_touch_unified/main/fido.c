#include "fido.h"
#include "fido_core.h"
#include "fido_hid.h"
#include "fido_platform.h"
#include "fingerprint.h"
#include "usb_descriptors.h"

#include <stdatomic.h>
#include <string.h>

#include "bootloader_random.h"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "esp_partition.h"
#include "tusb.h"

typedef struct {
  uint32_t channel;
  uint32_t generation;
  size_t size;
  uint8_t data[FIDO_MAX_MESSAGE];
} fido_job_t;

typedef struct {
  uint32_t generation;
  size_t size;
  uint8_t data[FIDO_RESPONSE_MAX];
} fido_result_t;

static QueueHandle_t reports, jobs, results;
static SemaphoreHandle_t core_mutex;
static nvs_handle_t storage;
static bool storage_open;
static fido_hid_t hid;
static atomic_bool operation_active, cancelled, waiting_for_user;
static atomic_bool invalidate_session, maintenance, initialized;
static atomic_int finger_count;
static atomic_size_t resident_count;
static atomic_bool receive_overflow;

bool fido_ready(void) { return initialized; }
bool fido_operation_active(void) { return operation_active; }
size_t fido_resident_count(void) { return resident_count; }
void fido_sensor_count_changed(int count) { finger_count = count; }

fido_storage_result_t fido_platform_read(const char *key, void *data, size_t *size) {
  if (!storage_open) return FIDO_STORAGE_ERROR;
  esp_err_t error = nvs_get_blob(storage, key, data, size);
  if (error == ESP_ERR_NVS_NOT_FOUND) return FIDO_STORAGE_NOT_FOUND;
  return error == ESP_OK ? FIDO_STORAGE_OK : FIDO_STORAGE_ERROR;
}

bool fido_platform_write(const char *key, const void *data, size_t size) {
  return storage_open && nvs_set_blob(storage, key, data, size) == ESP_OK &&
      nvs_commit(storage) == ESP_OK;
}

bool fido_platform_erase(void) {
  return storage_open && nvs_erase_all(storage) == ESP_OK && nvs_commit(storage) == ESP_OK;
}

int fido_platform_entropy(void *context, uint8_t *data, size_t size) {
  (void)context;
  // The radio is disabled. Enable the SAR entropy source while seeding or
  // reseeding mbedTLS; esp_fill_random alone is not a CSPRNG in that state.
  bootloader_random_enable();
  esp_fill_random(data, size);
  bootloader_random_disable();
  return 0;
}

uint32_t fido_platform_time_ms(void) { return (uint32_t)(esp_timer_get_time() / 1000); }
bool fido_platform_uv_configured(void) { return finger_count > 0 && fingerprint_is_ready(); }
bool fido_platform_cancelled(void) { return cancelled; }

fido_status_t fido_platform_verify_user(void) {
  waiting_for_user = true;
  fingerprint_verification_t result = fingerprint_verify_fresh(fido_platform_cancelled);
  waiting_for_user = false;
  switch (result) {
    case FINGERPRINT_VERIFIED: return FIDO_OK;
    case FINGERPRINT_VERIFY_TIMEOUT: return FIDO_ERR_USER_TIMEOUT;
    case FINGERPRINT_VERIFY_CANCELLED: return FIDO_ERR_CANCELLED;
    case FINGERPRINT_VERIFY_BUSY: return FIDO_ERR_OPERATION_DENIED;
  }
  return FIDO_ERR_OTHER;
}

static bool send_report(const uint8_t report[64]) {
  uint32_t started = fido_platform_time_ms();
  while (tud_mounted() && (uint32_t)(fido_platform_time_ms() - started) < 200) {
    if (tud_hid_n_ready(TINYTOUCH_FIDO_HID_INSTANCE) &&
        tud_hid_n_report(TINYTOUCH_FIDO_HID_INSTANCE, 0, report, 64)) return true;
    vTaskDelay(pdMS_TO_TICKS(1));
  }
  return false;
}

static bool start_request(uint32_t channel, uint32_t generation,
                            const uint8_t *data, size_t size) {
  if (maintenance) return false;
  fido_job_t job = {.channel = channel, .generation = generation, .size = size};
  memcpy(job.data, data, size);
  cancelled = false;
  operation_active = true;
  if (xQueueSend(jobs, &job, 0) == pdTRUE) return true;
  operation_active = false;
  return false;
}

static void cancel_request(bool invalidate) {
  cancelled = true;
  if (invalidate) invalidate_session = true;
}

void fido_receive_report(const uint8_t *data, size_t size) {
  if (reports && size == 64 && xQueueSend(reports, data, 0) != pdTRUE)
    receive_overflow = true;
}

static void worker_task(void *argument) {
  (void)argument;
  fido_job_t job;
  fido_result_t result;
  for (;;) {
    if (xQueueReceive(jobs, &job, portMAX_DELAY) != pdTRUE) continue;
    xSemaphoreTake(core_mutex, portMAX_DELAY);
    if (atomic_exchange(&invalidate_session, false)) fido_core_invalidate();
    result.generation = job.generation;
    result.size = fido_core_request(job.channel, job.data, job.size, result.data);
    initialized = fido_core_ready();
    resident_count = fido_core_resident_count();
    xSemaphoreGive(core_mutex);
    xQueueSend(results, &result, portMAX_DELAY);
  }
}

static void io_task(void *argument) {
  (void)argument;
  uint8_t report[64];
  fido_result_t result;
  bool mounted = false;
  for (;;) {
    bool connected = tud_mounted();
    if (mounted && !connected) {
      fido_hid_disconnect(&hid);
      xQueueReset(reports);
    }
    mounted = connected;
    if (atomic_exchange(&receive_overflow, false)) {
      fido_hid_disconnect(&hid);
      xQueueReset(reports);
    }
    if (xQueueReceive(results, &result, 0) == pdTRUE) {
      fido_hid_complete(&hid, result.generation, result.data, result.size);
      operation_active = false;
    }
    if (xQueueReceive(reports, report, pdMS_TO_TICKS(10)) == pdTRUE && mounted)
      fido_hid_receive(&hid, report, fido_platform_time_ms());
    fido_hid_tick(&hid, fido_platform_time_ms(), waiting_for_user);
  }
}

bool fido_factory_reset(void) {
  if (!core_mutex || atomic_exchange(&maintenance, true)) return false;
  bool ok = false;
  if (!operation_active && xSemaphoreTake(core_mutex, 0) == pdTRUE) {
    if (!storage_open) {
      if (!esp_partition_find_first(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_DATA_NVS, "fido")) {
        // An OTA installed over the old partition table has no FIDO state.
        ok = true;
      } else if (nvs_flash_erase_partition("fido") == ESP_OK &&
                 nvs_flash_init_partition("fido") == ESP_OK &&
                 nvs_open_from_partition("fido", "authenticator", NVS_READWRITE, &storage) == ESP_OK) {
        storage_open = true;
        ok = fido_core_init();
      }
    } else {
      ok = fido_core_reset();
    }
    initialized = fido_core_ready();
    resident_count = fido_core_resident_count();
    xSemaphoreGive(core_mutex);
  }
  maintenance = false;
  return ok;
}

void fido_start(int enrolled_fingers) {
  finger_count = enrolled_fingers;
  core_mutex = xSemaphoreCreateMutex();
  reports = xQueueCreate(80, 64);
  jobs = xQueueCreate(1, sizeof(fido_job_t));
  results = xQueueCreate(1, sizeof(fido_result_t));
  configASSERT(core_mutex && reports && jobs && results);
  esp_err_t error = nvs_flash_init_partition("fido");
  if (error == ESP_OK) error = nvs_open_from_partition("fido", "authenticator",
                                                      NVS_READWRITE, &storage);
  storage_open = error == ESP_OK;
  if (!storage_open) {
    ESP_LOGE("fido", "FIDO storage unavailable: %s", esp_err_to_name(error));
  } else {
    initialized = fido_core_init();
  }
  if (storage_open && !initialized) {
    ESP_LOGE("fido", "FIDO initialization failed; preserving stored credentials");
  }
  resident_count = fido_core_resident_count();
  const fido_hid_callbacks_t callbacks = {
    .send = send_report, .request = start_request, .cancel = cancel_request,
  };
  fido_hid_init(&hid, &callbacks);
  configASSERT(xTaskCreate(worker_task, "fido_worker", 16384, NULL, 4, NULL) == pdPASS);
  configASSERT(xTaskCreate(io_task, "fido_usb", 8192, NULL, 5, NULL) == pdPASS);
}
