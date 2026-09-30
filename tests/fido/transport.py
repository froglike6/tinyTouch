# Copyright (c) 2026 froglike6. SPDX-License-Identifier: MIT
"""Drive production CTAPHID and CTAP code through the host executable."""

from collections.abc import Callable, Iterator
from dataclasses import dataclass
from enum import StrEnum
from subprocess import Popen
from threading import Event
from typing import Final, Protocol, override

from fido2.ctap import STATUS, CtapDevice, CtapError

REPORT_SIZE: Final = 64
BROADCAST: Final = 0xFFFFFFFF
KEEPALIVE: Final = 0xBB
ERROR: Final = 0x3F


class HarnessFault(StrEnum):
    """Failures of the host harness, distinct from CTAP status errors."""

    REPORT = "Missing or invalid HID reports"
    SEQUENCE = "Device continuation sequence is invalid"
    TRUNCATED = "Device response is truncated"
    NONCE = "INIT did not echo the nonce"
    PIPES = "Host pipes are unavailable"
    EXITED = "Host exited without completing the command"
    CHANNEL = "Response was sent to a different channel"
    COMMAND = "Response command differs from request"
    BUILD = "Set IDF_PATH or FIDO_HOST_BINARY to run FIDO tests"
    COMPILER = "CMake is unavailable"


class HostOutput(Protocol):
    """The Popen process uses text mode, so each line is a string."""

    def readline(self) -> str:
        """Read a line from the text-mode pipe."""
        ...


class HarnessError(RuntimeError):
    """The host protocol failed before a CTAP response was available."""

    def __init__(self, fault: HarnessFault) -> None:
        """Record the typed failure and its user-readable description."""
        self.fault: HarnessFault = fault
        super().__init__(fault.value)


@dataclass(frozen=True, slots=True)
class HidMessage:
    """A complete CTAPHID message, independent of fragmentation."""

    channel: int
    command: int
    data: bytes


def frames(message: HidMessage) -> tuple[bytes, ...]:
    """Encode a message in the same wire format used by an actual USB host."""
    prefix = message.channel.to_bytes(4, "big")
    reports = [
        (prefix + bytes([message.command | 0x80])
         + len(message.data).to_bytes(2, "big") + message.data[:57]).ljust(64, b"\0"),
    ]
    for sequence, offset in enumerate(range(57, len(message.data), 59)):
        reports.append(
            (prefix + bytes([sequence]) + message.data[offset:offset + 59]).ljust(64, b"\0"),
        )
    return tuple(reports)


def reassemble(reports: tuple[bytes, ...]) -> HidMessage:
    """Reject a malformed device response instead of hiding a framing defect."""
    if not reports or any(len(report) != REPORT_SIZE for report in reports):
        raise HarnessError(HarnessFault.REPORT)
    first = reports[0]
    channel = int.from_bytes(first[:4], "big")
    length = int.from_bytes(first[5:7], "big")
    payload = bytearray(first[7:])
    for sequence, report in enumerate(reports[1:]):
        if report[:4] != first[:4] or report[4] != sequence:
            raise HarnessError(HarnessFault.SEQUENCE)
        payload.extend(report[5:])
    if len(payload) < length:
        raise HarnessError(HarnessFault.TRUNCATED)
    return HidMessage(channel, first[4] & 0x7F, bytes(payload[:length]))


class HostDevice(CtapDevice):
    """Mutable transport state belongs to one host process and USB channel."""

    def __init__(self, process: Popen[str]) -> None:
        """Allocate a channel on the running host process."""
        self.process: Popen[str] = process
        if process.stdout is None:
            raise HarnessError(HarnessFault.PIPES)
        self.reader: HostOutput = process.stdout
        nonce = b"tinytest"
        reply = self.exchange(HidMessage(BROADCAST, 6, nonce))
        if reply.data[:8] != nonce:
            raise HarnessError(HarnessFault.NONCE)
        self.channel: int = int.from_bytes(reply.data[8:12], "big")

    @property
    @override
    def capabilities(self) -> int:
        """Match the capabilities returned by the production INIT response."""
        return 0x0C

    @classmethod
    @override
    def list_devices(cls) -> Iterator[CtapDevice]:
        """Require an explicit test process without discovering physical devices."""
        return iter(())

    def command(self, command: str) -> tuple[bytes, ...]:
        """Send a test-platform control or a single raw USB report."""
        stdin = self.process.stdin
        stdout = self.process.stdout
        if stdin is None or stdout is None:
            raise HarnessError(HarnessFault.PIPES)
        _ = stdin.write(command + "\n")
        stdin.flush()
        output: list[bytes] = []
        while True:
            line = self.reader.readline().strip()
            if line == "END":
                return tuple(output)
            if not line:
                raise HarnessError(HarnessFault.EXITED)
            output.append(bytes.fromhex(line))

    def send(self, report: bytes) -> tuple[bytes, ...]:
        """Deliver one raw report to the firmware transport."""
        return self.command("R " + report.hex())

    def exchange(self, message: HidMessage) -> HidMessage:
        """Complete a transport exchange including queued authenticator work."""
        replies: list[bytes] = []
        for report in frames(message):
            replies.extend(self.send(report))
        replies.extend(self.command("P"))
        return reassemble(tuple(replies))

    def raw(self, payload: bytes, channel: int = 1) -> bytes:
        """Bypass framing to test malformed CBOR and authenticator session rules."""
        return self.command(f"C {channel:x} {payload.hex()}")[0]

    @override
    def call(
        self,
        cmd: int,
        data: bytes = b"",
        event: Event | None = None,
        on_keepalive: Callable[[STATUS], None] | None = None,
    ) -> bytes:
        """Use real CTAPHID fragmentation before the Yubico client sees CTAP."""
        replies: list[bytes] = []
        for report in frames(HidMessage(self.channel, cmd, data)):
            replies.extend(self.send(report))
        if event is not None and event.is_set():
            replies.extend(self.send(frames(HidMessage(self.channel, 0x11, b""))[0]))
        replies.extend(self.command("P"))
        if on_keepalive is not None:
            for report in replies:
                if report[4] == KEEPALIVE:
                    on_keepalive(STATUS(report[7]))
        response = reassemble(tuple(report for report in replies if report[4] != KEEPALIVE))
        if response.channel != self.channel:
            raise HarnessError(HarnessFault.CHANNEL)
        if response.command == ERROR:
            raise CtapError(response.data[0])
        if response.command != cmd:
            raise HarnessError(HarnessFault.COMMAND)
        return response.data
