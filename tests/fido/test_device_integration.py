# Copyright (c) 2026 froglike6. SPDX-License-Identifier: MIT
import subprocess
from pathlib import Path

import pytest


def test_usb_endpoint_budget_and_fido_descriptor(host_binary: Path) -> None:
    _ = subprocess.run(
        [str(host_binary.parent / "fido-usb-descriptors")],
        check=True, capture_output=True, text=True, timeout=5,
    )


@pytest.mark.parametrize("case", [
    "fresh_verified", "fresh_held", "fresh_wrong", "fresh_cancel",
    "fresh_cancel_during_match", "fresh_busy", "fresh_clock_wrap",
])
def test_fingerprint_requires_fresh_matching_touch(host_binary: Path, case: str) -> None:
    _ = subprocess.run(
        [str(host_binary.parent / "fido-fingerprint"), case],
        check=True, capture_output=True, text=True, timeout=5,
    )
