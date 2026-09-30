---
title: FIDO2 development firmware
description: USB FIDO2 support in the personal tinyTouch fork, installation, and verification.
---

# FIDO2 development firmware

The personal fork's `feature/fido2` branch adds FIDO2 to the custom LED firmware.
Version `0.2.0-dev.1` exposes a USB FIDO HID interface alongside the existing
PIV smart card, keyboard, and CDC configuration console.

## Supported operations

- CTAP2.0 `GetInfo`, `MakeCredential`, `GetAssertion`, `GetNextAssertion`, and
  `Reset` over CTAPHID, including initialization, ping, cancellation, and keepalive.
- ES256 (P-256/SHA-256) credentials with packed self attestation. There is no
  attestation certificate or manufacturer trust chain.
- Up to 16 discoverable credentials (passkeys), plus wrapped credentials supplied
  by a relying party. Creating another discoverable credential for the same
  relying party and user ID replaces the previous one and invalidates its handle.
- Fingerprint user verification. Interactive registration and authentication
  require a fresh match against an enrolled sensor template. Lift a finger already
  on the sensor, then touch it again. The prompt expires after 30 seconds.
- Persistent credentials and a shared signature counter that is saved before
  returning a signature. Invalid storage or failed writes stop the operation.

CTAP reset is allowed only in the first ten seconds after boot and requires a
fresh fingerprint match. It rotates the wrapping key and deletes all FIDO2
credentials, including credentials that a relying party retained. PIV keys and
sensor templates remain intact. The existing factory reset and physical recovery
also clear the FIDO partition.

Keyboard auto-PIN and background fingerprint handling pause during FIDO requests.
A previous PIV authorization does not satisfy FIDO user verification. Sensor LED
idle fading and brief green/red authentication feedback remain enabled.

Client PIN, U2F/CTAP1, CTAP2.1 features, credential management, and extensions are
not implemented or advertised. Sites that require enterprise attestation or
unsupported algorithms may reject this authenticator. This is development
firmware, without FIDO certification or a secure element. The wrapping key lives
in device NVS and inherits the board's flash protection; wrapping does not prevent
credential extraction from an unprotected flash dump. Fingerprint matching also
inherits the existing sensor's unauthenticated UART connection.

## USB and storage layout

The ESP32-S3 permits five IN endpoints including endpoint zero. Adding FIDO HID
uses the endpoint previously assigned to unused CDC serial-state notifications.
The CDC console keeps its control interface and bulk data endpoints, with no
notification endpoint. The USB device revision is `0x0200` so hosts can recognize
the descriptor change.

Existing partition addresses remain unchanged. A 64 KiB NVS partition named
`fido` is added at `0x213000`, after the recovery request sector. Firmware checks
stored credentials and fails closed on corruption instead of silently erasing
them. `STATUS` includes `fido=ready|unavailable` and `passkeys=N`.

Installing the application alone with the old partition table leaves FIDO
unavailable. The first installation needs USB download mode and the new partition
table. Subsequent application updates can use the existing OTA path with a
matching signing key.

## Build

Use ESP-IDF 5.3.x; local verification used 5.3.5. Install the SDK's ESP32-S3 tools
and activate its environment before building. Components are pinned by the
manifest and lock file, including TinyUSB and TinyCBOR.

```sh
git clone --branch feature/fido2 https://github.com/froglike6/tinyTouch.git
cd tinyTouch
source /path/to/esp-idf/export.sh
espsecure.py generate_signing_key --version 2 \
  firmware/tiny_touch_unified/secure_boot_signing_key.pem
chmod 600 firmware/tiny_touch_unified/secure_boot_signing_key.pem
idf.py -C firmware/tiny_touch_unified build
idf.py -C firmware/tiny_touch_unified \
  -B firmware/tiny_touch_unified/build-recovery \
  -D TINYTOUCH_RECOVERY_BUILD=ON build
python release/assemble-release.py \
  --firmware-build firmware/tiny_touch_unified/build \
  --recovery-build firmware/tiny_touch_unified/build-recovery
```

Generate a signing key only when one does not already exist. Keep it private and
reuse it for later OTA builds. The local LED devices use their existing local
signing key; a newly generated key requires USB installation.

## Install on an existing device

Back up device configuration and PIV state with the existing CLI before flashing.
Enter USB download mode by reconnecting USB while holding BOOT. Write the four
factory images individually, using the actual download-mode serial port:

```sh
esptool.py --chip esp32s3 --port /dev/cu.usbmodemPORT \
  write_flash --flash_mode dio --flash_freq 80m --flash_size 4MB \
  0x0 dist/release/factory/bootloader.bin \
  0x8000 dist/release/factory/partition-table.bin \
  0x10000 dist/release/factory/tiny_touch_unified.bin \
  0x210000 dist/release/factory/ota_data_initial.bin
```

Then reconnect without BOOT. This layout preserves the existing configuration
and PIV NVS region at `0x9000` and does not touch sensor templates. Do not use
`erase_flash` or the merged full image on a configured device: the merged image
contains padding over the existing NVS region. Recovery images deliberately clear
device credentials and are not an update method.

Check the CLI status, existing PIV login, ring fading, and touch wake-up after
installation. For FIDO, register a security key on a test account and sign in
with a fresh fingerprint touch. Test the browser on the target OS before using
these credentials for a primary account.

## Verification

The host suite compiles the production CTAP, CBOR, credential storage, and crypto
code against ESP-IDF's mbedTLS, with address and undefined-behavior sanitizers.
Only hardware access, clock, and persistent storage I/O are simulated. Yubico's
`python-fido2` decodes the responses, checks real self attestation and assertion
signatures, and completes registration/login through `Fido2Server`.

The suite also compiles the real USB descriptor source against TinyUSB headers
and the real fingerprint driver against scripted UART responses. It checks the
endpoint budget, fresh-finger requirement, cancellation, restart persistence,
counter writes, credential limits, malformed CBOR, and CTAPHID framing.

After an ESP-IDF build has downloaded the managed components:

```sh
uv run --python 3.12 --with fido2==2.1.1 --with pytest==8.4.2 \
  pytest tests/fido -q
uv run --python 3.12 --with fido2==2.1.1 --with pytest==8.4.2 \
  --with basedpyright==1.40.1 --with ruff==0.16.9 \
  basedpyright --project tests/fido/pyproject.toml
uv run --python 3.12 --with ruff==0.16.9 ruff check tests/fido
```

Local host verification passes 56 FIDO tests and 118 existing tests. Actual
ESP32-S3 USB enumeration, the CDC console on macOS, simultaneous PIV/FIDO use,
and browser interaction with a physical device still require hardware testing.
The host suite does not establish FIDO certification or physical sensor behavior.

Protocol reference: [FIDO CTAP2.0 specification](https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html).
