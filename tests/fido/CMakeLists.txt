cmake_minimum_required(VERSION 3.16)
project(tinytouch_fido_host C)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(FIDO_MAIN "${CMAKE_CURRENT_LIST_DIR}/../../firmware/tiny_touch_unified/main")
set(CBOR_SOURCE "${CMAKE_CURRENT_LIST_DIR}/../../firmware/tiny_touch_unified/managed_components/espressif__cbor/tinycbor/src")
if(NOT DEFINED MBEDTLS_SOURCE)
  message(FATAL_ERROR "Pass -DMBEDTLS_SOURCE=<ESP-IDF>/components/mbedtls/mbedtls")
endif()
set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
add_subdirectory("${MBEDTLS_SOURCE}" mbedtls)
add_library(fido_cbor STATIC
  "${CBOR_SOURCE}/cborencoder.c"
  "${CBOR_SOURCE}/cborencoder_close_container_checked.c"
  "${CBOR_SOURCE}/cborparser.c"
  "${CBOR_SOURCE}/cborvalidation.c"
)
target_include_directories(fido_cbor PUBLIC "${CBOR_SOURCE}")
target_compile_definitions(fido_cbor PRIVATE CBOR_PARSER_MAX_RECURSIONS=16)
add_executable(fido-host host.c
  "${FIDO_MAIN}/fido_cbor.c" "${FIDO_MAIN}/fido_core.c"
  "${FIDO_MAIN}/fido_crypto.c" "${FIDO_MAIN}/fido_hid.c"
  "${FIDO_MAIN}/fido_request.c" "${FIDO_MAIN}/fido_response.c"
  "${FIDO_MAIN}/fido_store.c"
)
target_include_directories(fido-host PRIVATE "${FIDO_MAIN}")
target_compile_options(fido-host PRIVATE -Wall -Wextra -Werror -pedantic)
target_link_libraries(fido-host PRIVATE fido_cbor mbedcrypto)
set(TINYUSB_SOURCE "${CMAKE_CURRENT_LIST_DIR}/../../firmware/tiny_touch_unified/managed_components/espressif__tinyusb/src")
add_executable(fido-usb-descriptors usb_descriptors_test.c "${FIDO_MAIN}/usb_descriptors.c")
target_include_directories(fido-usb-descriptors PRIVATE "${FIDO_MAIN}" "${TINYUSB_SOURCE}" stubs)
target_compile_definitions(fido-usb-descriptors PRIVATE CFG_TUSB_CONFIG_FILE="usb_test_config.h")
target_compile_options(fido-usb-descriptors PRIVATE -Wall -Wextra -Werror)
add_executable(fido-fingerprint "${CMAKE_CURRENT_LIST_DIR}/../firmware/fingerprint_driver_test.c"
  "${FIDO_MAIN}/fingerprint.c" "${FIDO_MAIN}/fingerprint_led.c")
target_include_directories(fido-fingerprint PRIVATE "${CMAKE_CURRENT_LIST_DIR}/../firmware/stubs")
target_compile_options(fido-fingerprint PRIVATE -Wall -Wextra -Werror -pedantic)
option(FIDO_SANITIZERS "Check host memory and undefined behavior" OFF)
if(FIDO_SANITIZERS)
  target_compile_options(fido-host PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
  target_link_options(fido-host PRIVATE -fsanitize=address,undefined)
  target_compile_options(fido_cbor PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
endif()
