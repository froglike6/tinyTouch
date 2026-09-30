# Copyright (c) 2026 froglike6. SPDX-License-Identifier: MIT
import subprocess
from pathlib import Path

import pytest
from fido2 import cbor
from fido2.ctap import CtapError
from fido2.ctap2.base import Ctap2

from test_credentials import CHALLENGE, LOGIN, create
from transport import HostDevice


def test_credentials_and_counter_survive_restart(host_binary: Path, tmp_path: Path) -> None:
    with subprocess.Popen(
        [str(host_binary), str(tmp_path)], stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, text=True, bufsize=1,
    ) as process:
        original = HostDevice(process)
        registered = create(Ctap2(original), resident=True).auth_data
        credential = registered.credential_data
        assert credential is not None
    with subprocess.Popen(
        [str(host_binary), str(tmp_path)], stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, text=True, bufsize=1,
    ) as process:
        restarted = HostDevice(process)
        assertion = Ctap2(restarted).get_assertion("example.com", LOGIN, options={"uv": True})
        credential.public_key.verify(assertion.auth_data + LOGIN, assertion.signature)
        assert assertion.auth_data.counter > registered.counter


def test_write_failure_cannot_return_a_credential(device: HostDevice) -> None:
    ctap = Ctap2(device)
    _ = device.command("F 1")
    with pytest.raises(CtapError) as error:
        _ = create(ctap, resident=True)
    assert error.value.code == CtapError.ERR.OTHER
    assert int.from_bytes(device.command("Q")[0][4:], "big") == 0
    _ = device.command("F 0")
    _ = create(ctap, resident=True)
    _ = device.command("F 1")
    with pytest.raises(CtapError) as error:
        _ = ctap.get_assertion("example.com", LOGIN)
    assert error.value.code == CtapError.ERR.OTHER


def test_reset_rotates_nonresident_key_and_preserves_other_files(
    device: HostDevice, tmp_path: Path,
) -> None:
    piv = tmp_path / "piv"
    _ = piv.write_bytes(b"PIV state outside the authenticator namespace")
    ctap = Ctap2(device)
    credential = create(ctap, resident=True).auth_data.credential_data
    assert credential is not None
    ctap.reset()
    assert piv.read_bytes() == b"PIV state outside the authenticator namespace"
    assert int.from_bytes(device.command("Q")[0][4:], "big") == 0
    with pytest.raises(CtapError) as error:
        _ = ctap.get_assertion(
            "example.com", LOGIN, [{"type": "public-key", "id": credential.credential_id}],
        )
    assert error.value.code == CtapError.ERR.NO_CREDENTIALS


def test_entropy_failure_cannot_reset_or_replace_existing_keys(
    device: HostDevice, tmp_path: Path,
) -> None:
    credential = create(Ctap2(device), resident=True).auth_data.credential_data
    assert credential is not None
    snapshot = {file.name: file.read_bytes() for file in tmp_path.iterdir()}
    _ = device.command("E 1")
    _ = device.command("I")
    assert device.raw(b"\x04") == b"\x7f"
    _ = device.command("Z")
    assert snapshot == {file.name: file.read_bytes() for file in tmp_path.iterdir()}
    _ = device.command("E 0")
    _ = device.command("I")
    assertion = Ctap2(device).get_assertion("example.com", LOGIN)
    credential.public_key.verify(assertion.auth_data + LOGIN, assertion.signature)


def test_reset_requires_verification_and_boot_window(device: HostDevice) -> None:
    ctap = Ctap2(device)
    _ = device.command("U 47")
    with pytest.raises(CtapError) as error:
        ctap.reset()
    assert error.value.code == CtapError.ERR.USER_ACTION_TIMEOUT
    _ = device.command("U 0")
    _ = device.command("T 10001")
    before = device.command("Q")[0]
    with pytest.raises(CtapError) as error:
        ctap.reset()
    assert error.value.code == CtapError.ERR.NOT_ALLOWED
    assert before == device.command("Q")[0]


@pytest.mark.parametrize(("filename", "replacement"), [
    ("state", b"damaged state"), ("state", None), ("rk00", b"damaged credential"),
])
def test_corruption_does_not_erase_credentials(
    host_binary: Path, tmp_path: Path, filename: str, replacement: bytes | None,
) -> None:
    with subprocess.Popen(
        [str(host_binary), str(tmp_path)], stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, text=True, bufsize=1,
    ) as process:
        _ = create(Ctap2(HostDevice(process)), resident=True)
    target = tmp_path / filename
    if replacement is None:
        target.unlink()
    else:
        _ = target.write_bytes(replacement)
    snapshot = {file.name: file.read_bytes() for file in tmp_path.iterdir()}
    with subprocess.Popen(
        [str(host_binary), str(tmp_path)], stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, text=True, bufsize=1,
    ) as process:
        assert HostDevice(process).raw(b"\x04") == b"\x7f"
    assert snapshot == {file.name: file.read_bytes() for file in tmp_path.iterdir()}


def test_next_assertion_is_channel_and_time_scoped(device: HostDevice) -> None:
    ctap = Ctap2(device)
    _ = create(ctap, resident=True)
    _ = create(ctap, b"bob", resident=True)
    _ = ctap.get_assertion("example.com", LOGIN)
    assert device.raw(b"\x08", channel=12345) == b"\x30"
    _ = ctap.get_assertion("example.com", LOGIN)
    _ = device.command("T 30001")
    with pytest.raises(CtapError) as error:
        _ = ctap.get_next_assertion()
    assert error.value.code == CtapError.ERR.NOT_ALLOWED
    _ = ctap.get_assertion("example.com", LOGIN)
    _ = ctap.get_info()
    with pytest.raises(CtapError) as error:
        _ = ctap.get_next_assertion()
    assert error.value.code == CtapError.ERR.NOT_ALLOWED


def test_invalid_options_and_algorithm_are_rejected(device: HostDevice) -> None:
    message = {1: CHALLENGE, 2: {"id": "example.com"}, 3: {"id": b"alice"},
               4: [{"type": "public-key", "alg": -257}]}
    assert device.raw(b"\x01" + cbor.encode(message)) == b"\x26"
    message[4] = [{"type": "public-key", "alg": -7}]
    assert device.raw(b"\x01" + cbor.encode({**message, 7: {"up": False}})) == b"\x2c"
