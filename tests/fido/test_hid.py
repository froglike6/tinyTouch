# Copyright (c) 2026 froglike6. SPDX-License-Identifier: MIT
import hashlib

import pytest
from fido2 import cbor

from test_credentials import CHALLENGE
from transport import BROADCAST, HidMessage, HostDevice, frames, reassemble


@pytest.mark.parametrize("length", [0, 1, 57, 58, 116, 117, 4096])
def test_ping_fragments_round_trip(device: HostDevice, length: int) -> None:
    data = bytes(index & 0xFF for index in range(length))
    assert device.exchange(HidMessage(device.channel, 1, data)).data == data


@pytest.mark.parametrize("channel", [0, BROADCAST, 123456])
def test_unknown_channels_are_rejected(device: HostDevice, channel: int) -> None:
    response = device.exchange(HidMessage(channel, 1, b"ping"))
    assert response.command == 0x3F
    assert response.data == b"\x0b"


def test_invalid_length_and_sequence_abort_assembly(device: HostDevice) -> None:
    initial = bytearray(frames(HidMessage(device.channel, 1, b"x"))[0])
    initial[5:7] = (4097).to_bytes(2, "big")
    assert reassemble(device.send(bytes(initial))).data == b"\x03"
    message = frames(HidMessage(device.channel, 1, bytes(100)))
    assert not device.send(message[0])
    wrong_sequence = bytearray(message[1])
    wrong_sequence[4] = 1
    assert reassemble(device.send(bytes(wrong_sequence))).data == b"\x04"
    assert device.exchange(HidMessage(device.channel, 1, b"recovered")).data == b"recovered"


def test_incomplete_message_times_out_and_recovers(device: HostDevice) -> None:
    assert not device.send(frames(HidMessage(device.channel, 1, bytes(100)))[0])
    assert reassemble(device.command("T 500")).data == b"\x05"
    assert device.exchange(HidMessage(device.channel, 1, b"ok")).data == b"ok"


def test_timeout_handles_millisecond_wrap(device: HostDevice) -> None:
    _ = device.command("T 4294967200")
    assert not device.send(frames(HidMessage(device.channel, 1, bytes(100)))[0])
    assert not device.command("T 3")
    assert reassemble(device.command("T 500")).data == b"\x05"


def test_busy_and_keepalive_do_not_interrupt_owner(device: HostDevice) -> None:
    other = device.exchange(HidMessage(BROADCAST, 6, b"otherkey"))
    other_channel = int.from_bytes(other.data[8:12], "big")
    assert not device.send(frames(HidMessage(device.channel, 0x10, b"\x04"))[0])
    busy = reassemble(device.send(frames(HidMessage(other_channel, 1, b"x"))[0]))
    assert busy.data == b"\x06"
    keepalive = reassemble(device.command("T 100"))
    assert keepalive.command == 0x3B
    assert keepalive.data == b"\x02"
    response = reassemble(device.command("P"))
    assert response.channel == device.channel
    assert response.data[0] == 0


def test_other_channel_init_does_not_cancel_owner(device: HostDevice) -> None:
    other = device.exchange(HidMessage(BROADCAST, 6, b"otherkey"))
    other_channel = int.from_bytes(other.data[8:12], "big")
    assert not device.send(frames(HidMessage(device.channel, 0x10, b"\x04"))[0])
    initialized = reassemble(device.send(frames(HidMessage(other_channel, 6, b"resync00"))[0]))
    assert initialized.command == 6
    assert reassemble(device.command("P")).data[0] == 0


def test_owner_init_cancels_inflight_request_without_stale_response(device: HostDevice) -> None:
    request = b"\x01" + cbor.encode({
        1: CHALLENGE, 2: {"id": "example.com"}, 3: {"id": b"alice"},
        4: [{"type": "public-key", "alg": -7}], 7: {"rk": True},
    })
    for report in frames(HidMessage(device.channel, 0x10, request)):
        assert not device.send(report)
    reply = reassemble(device.send(frames(HidMessage(device.channel, 6, b"resync00"))[0]))
    assert reply.command == 6
    assert not device.command("P")
    assert device.command("Q")[0] == bytes(8)
    assert device.exchange(HidMessage(device.channel, 0x10, b"\x04")).data[0] == 0


def test_cancel_reply_and_disconnect_drop_previous_authorization(device: HostDevice) -> None:
    assert not device.send(frames(HidMessage(device.channel, 0x10, b"\x04"))[0])
    assert not device.send(frames(HidMessage(device.channel, 0x11, b""))[0])
    assert reassemble(device.command("P")).data == b"\x2d"
    assert not device.send(frames(HidMessage(device.channel, 0x10, b"\x04"))[0])
    _ = device.command("D")
    assert not device.command("P")
    reply = device.exchange(HidMessage(device.channel, 1, b"x"))
    assert reply.data == b"\x0b"


def test_malformed_cbor_corpus_does_not_crash(device: HostDevice) -> None:
    for index in range(300):
        digest = hashlib.sha256(index.to_bytes(4, "big")).digest()
        length = digest[0] + 1
        payload = b"\x01" + (digest * 8)[:length]
        response = device.raw(payload)
        assert len(response) == 1
        assert response[0] != 0
