idf_component_register(
  SRCS
    "main.c"
    "config_console.c"
    "device_config.c"
    "fido.c"
    "fido_cbor.c"
    "fido_core.c"
    "fido_crypto.c"
    "fido_hid.c"
    "fido_request.c"
    "fido_response.c"
    "fido_store.c"
    "fingerprint.c"
    "fingerprint_led.c"
    "firmware_update.c"
    "piv.c"
    "touch_pin_hid.c"
    "usb_ccid.c"
    "usb_descriptors.c"
  INCLUDE_DIRS "."
  REQUIRES app_update bootloader_support cbor driver esp_partition esp_timer esp_tinyusb mbedtls nvs_flash
  PRIV_REQUIRES esp_driver_uart
)

# USB requests are untrusted; bound TinyCBOR's recursive parser and validator.
idf_component_get_property(cbor_lib espressif__cbor COMPONENT_LIB)
target_compile_definitions(${cbor_lib} PRIVATE CBOR_PARSER_MAX_RECURSIONS=16)

target_compile_definitions(
  ${COMPONENT_LIB} PRIVATE
  TINYTOUCH_FIRMWARE_VERSION="${TINYTOUCH_VERSION}"
  TINYTOUCH_BUILD_ID="${TINYTOUCH_BUILD_ID}"
  TINYTOUCH_PROTOCOL_VERSION=6
)

if(TINYTOUCH_DEVELOPMENT_SKIP_FINGERPRINT_AUTH)
  target_compile_definitions(${COMPONENT_LIB} PRIVATE
    TINYTOUCH_DEVELOPMENT_SKIP_FINGERPRINT_AUTH=1)
endif()

if(TINYTOUCH_RECOVERY_BUILD)
  target_compile_definitions(${COMPONENT_LIB} PRIVATE TINYTOUCH_RECOVERY_BUILD=1)
endif()
