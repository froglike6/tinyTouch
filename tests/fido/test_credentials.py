# Copyright (c) 2026 froglike6. SPDX-License-Identifier: MIT
import hashlib
from threading import Event
from typing import Final

import pytest
from cryptography.exceptions import InvalidSignature
from fido2 import cbor
from fido2.attestation.packed import PackedAttestation
from fido2.ctap import CtapError
from fido2.ctap2.base import AttestationResponse, Ctap2

from transport import HostDevice

CHALLENGE: Final = hashlib.sha256(b"registration challenge").digest()
LOGIN: Final = hashlib.sha256(b"authentication challenge").digest()


def create(ctap: Ctap2, user: bytes = b"alice", *, resident: bool = False) -> AttestationResponse:
    return ctap.make_credential(
        CHALLENGE, {"id": "example.com", "name": "Example"},
        {"id": user, "name": user.decode()}, [{"type": "public-key", "alg": -7}],
        options={"rk": resident, "uv": True},
    )


def test_get_info_advertises_only_implemented_protocol(device: HostDevice) -> None:
    info = Ctap2(device).info
    assert info.versions == ["FIDO_2_0"]
    assert info.options == {"rk": True, "up": True, "uv": True}
    assert info.max_msg_size == 4096
    assert not info.pin_uv_protocols
    assert not info.extensions
    _ = device.command("V 0")
    assert Ctap2(device).info.options["uv"] is False


def test_registration_and_assertion_signatures(device: HostDevice) -> None:
    ctap = Ctap2(device)
    registration = create(ctap)
    credential = registration.auth_data.credential_data
    assert credential is not None
    assert len(credential.credential_id) == 61
    assert registration.auth_data.flags == 0x45
    assert registration.auth_data.rp_id_hash == hashlib.sha256(b"example.com").digest()
    _ = PackedAttestation().verify(registration.att_stmt, registration.auth_data, CHALLENGE)
    assertion = ctap.get_assertion(
        "example.com", LOGIN,
        [{"type": "public-key", "id": credential.credential_id}], options={"uv": True},
    )
    credential.public_key.verify(assertion.auth_data + LOGIN, assertion.signature)
    assert assertion.auth_data.flags == 0x05
    assert assertion.auth_data.counter > registration.auth_data.counter
    with pytest.raises(InvalidSignature):
        credential.public_key.verify(assertion.auth_data + CHALLENGE, assertion.signature)


def test_rp_binding_and_tampered_handle_are_rejected(device: HostDevice) -> None:
    ctap = Ctap2(device)
    credential = create(ctap).auth_data.credential_data
    assert credential is not None
    for rp, identifier in (
        ("different.example", credential.credential_id),
        ("example.com", credential.credential_id[:-1] + bytes([credential.credential_id[-1] ^ 1])),
    ):
        with pytest.raises(CtapError) as error:
            _ = ctap.get_assertion(rp, LOGIN, [{"type": "public-key", "id": identifier}])
        assert error.value.code == CtapError.ERR.NO_CREDENTIALS


def test_discoverable_credentials_and_next_assertion(device: HostDevice) -> None:
    ctap = Ctap2(device)
    alice = create(ctap, resident=True).auth_data.credential_data
    bob = create(ctap, b"bob", resident=True).auth_data.credential_data
    assert alice is not None
    assert bob is not None
    first = ctap.get_assertion("example.com", LOGIN, options={"uv": True})
    assert first.number_of_credentials == 2
    assert first.user == {"id": b"bob", "name": "bob"}
    bob.public_key.verify(first.auth_data + LOGIN, first.signature)
    second = ctap.get_next_assertion()
    assert second.user == {"id": b"alice", "name": "alice"}
    alice.public_key.verify(second.auth_data + LOGIN, second.signature)
    with pytest.raises(CtapError) as error:
        _ = ctap.get_next_assertion()
    assert error.value.code == CtapError.ERR.NOT_ALLOWED


def test_resident_limit_and_same_account_replacement(device: HostDevice) -> None:
    ctap = Ctap2(device)
    for index in range(16):
        _ = create(ctap, f"user{index}".encode(), resident=True)
    assert int.from_bytes(device.command("Q")[0][4:], "big") == 16
    with pytest.raises(CtapError) as error:
        _ = create(ctap, b"overflow", resident=True)
    assert error.value.code == CtapError.ERR.KEY_STORE_FULL
    _ = create(ctap, b"user0", resident=True)
    assert int.from_bytes(device.command("Q")[0][4:], "big") == 16
    _ = create(ctap, b"nonresident")


def test_verification_failure_never_creates_a_key(device: HostDevice) -> None:
    ctap = Ctap2(device)
    _ = device.command("U 47")
    with pytest.raises(CtapError) as error:
        _ = create(ctap, resident=True)
    assert error.value.code == CtapError.ERR.USER_ACTION_TIMEOUT
    assert int.from_bytes(device.command("Q")[0][4:], "big") == 0
    _ = device.command("U 0")
    _ = device.command("V 0")
    with pytest.raises(CtapError) as error:
        _ = create(ctap)
    assert error.value.code == CtapError.ERR.OPERATION_DENIED


def test_replaced_resident_handle_is_revoked(device: HostDevice) -> None:
    ctap = Ctap2(device)
    old = create(ctap, resident=True).auth_data.credential_data
    nonresident = create(ctap, b"bob").auth_data.credential_data
    replacement = create(ctap, resident=True).auth_data.credential_data
    assert old is not None
    assert nonresident is not None
    assert replacement is not None
    assert replacement.credential_id != old.credential_id
    for identifier in (old.credential_id, b"\x01" + old.credential_id[1:]):
        with pytest.raises(CtapError) as error:
            _ = ctap.get_assertion(
                "example.com", LOGIN, [{"type": "public-key", "id": identifier}],
            )
        assert error.value.code == CtapError.ERR.NO_CREDENTIALS
    for credential in (replacement, nonresident):
        assertion = ctap.get_assertion(
            "example.com", LOGIN,
            [{"type": "public-key", "id": credential.credential_id}],
        )
        credential.public_key.verify(assertion.auth_data + LOGIN, assertion.signature)
    registered = ctap.make_credential(
        CHALLENGE, {"id": "example.com"}, {"id": b"alice"},
        [{"type": "public-key", "alg": -7}],
        exclude_list=[{"type": "public-key", "id": old.credential_id}],
    )
    assert registered.auth_data.credential_data is not None


def test_exclusion_requires_verification_before_disclosure(device: HostDevice) -> None:
    ctap = Ctap2(device)
    credential = create(ctap).auth_data.credential_data
    assert credential is not None
    _ = device.command("U 47")
    with pytest.raises(CtapError) as error:
        _ = ctap.make_credential(
            CHALLENGE, {"id": "example.com"}, {"id": b"alice"},
            [{"type": "public-key", "alg": -7}],
            exclude_list=[{"type": "public-key", "id": credential.credential_id}],
        )
    assert error.value.code == CtapError.ERR.USER_ACTION_TIMEOUT
    _ = device.command("U 0")
    with pytest.raises(CtapError) as error:
        _ = ctap.make_credential(
            CHALLENGE, {"id": "example.com"}, {"id": b"alice"},
            [{"type": "public-key", "alg": -7}],
            exclude_list=[{"type": "public-key", "id": credential.credential_id}],
        )
    assert error.value.code == CtapError.ERR.CREDENTIAL_EXCLUDED


def test_silent_probe_has_no_presence_or_verification_flags(device: HostDevice) -> None:
    ctap = Ctap2(device)
    credential = create(ctap).auth_data.credential_data
    assert credential is not None
    before = device.command("Q")[0][:4]
    response = ctap.get_assertion(
        "example.com", LOGIN, [{"type": "public-key", "id": credential.credential_id}],
        options={"up": False, "uv": False},
    )
    assert response.auth_data.flags == 0
    assert device.command("Q")[0][:4] == before
    credential.public_key.verify(response.auth_data + LOGIN, response.signature)


def test_cancel_does_not_create_a_credential(device: HostDevice) -> None:
    ctap = Ctap2(device)
    cancelled = Event()
    cancelled.set()
    with pytest.raises(CtapError) as error:
        _ = ctap.make_credential(
            CHALLENGE, {"id": "example.com"}, {"id": b"alice"},
            [{"type": "public-key", "alg": -7}], options={"rk": True}, event=cancelled,
        )
    assert error.value.code == CtapError.ERR.KEEPALIVE_CANCEL
    assert int.from_bytes(device.command("Q")[0][4:], "big") == 0


@pytest.mark.parametrize(("payload", "status"), [
    (b"\x01\xff", 0x12),
    (b"\x01\xa0\x00", 0x12),
    (b"\x01\xa2\x01\x00\x01\x00", 0x12),
    (b"\x01\x80", 0x11),
    (b"\x01\xa0", 0x14),
    (b"\x04\xa0", 0x03),
    (b"\x06", 0x01),
    (b"\x01" + b"\x81" * 100 + b"\x00", 0x12),
])
def test_invalid_messages_fail_closed(device: HostDevice, payload: bytes, status: int) -> None:
    assert device.raw(payload) == bytes([status])


def test_pin_auth_cannot_bypass_biometrics(device: HostDevice) -> None:
    message = {1: CHALLENGE, 2: {"id": "example.com"}, 3: {"id": b"alice"},
               4: [{"type": "public-key", "alg": -7}], 8: bytes(16), 9: 1}
    assert device.raw(b"\x01" + cbor.encode(message)) == b"\x33"
    assert device.command("Q")[0] == bytes(8)
