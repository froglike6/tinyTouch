# Copyright (c) 2026 froglike6. SPDX-License-Identifier: MIT
"""Build and run the real firmware core without touching connected devices."""

import os
import shutil
import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest

from transport import HarnessError, HarnessFault, HostDevice


@pytest.fixture(scope="session")
def host_binary(tmp_path_factory: pytest.TempPathFactory) -> Path:
    configured = os.environ.get("FIDO_HOST_BINARY")
    if configured:
        return Path(configured)
    idf_path = os.environ.get("IDF_PATH")
    if not idf_path:
        raise HarnessError(HarnessFault.BUILD)
    cmake = shutil.which("cmake")
    if cmake is None:
        raise HarnessError(HarnessFault.COMPILER)
    build = tmp_path_factory.mktemp("fido-build")
    source = Path(__file__).parent
    _ = subprocess.run(
        [cmake, "-S", str(source), "-B", str(build),
         f"-DMBEDTLS_SOURCE={idf_path}/components/mbedtls/mbedtls",
         "-DFIDO_SANITIZERS=ON", "-DCMAKE_BUILD_TYPE=Debug"],
        check=True, capture_output=True, text=True, timeout=60,
    )
    _ = subprocess.run(
        [cmake, "--build", str(build), "-j", "4"],
        check=True, text=True, timeout=180,
    )
    return build / "fido-host"


@pytest.fixture
def device(host_binary: Path, tmp_path: Path) -> Iterator[HostDevice]:
    with subprocess.Popen(
        [str(host_binary), str(tmp_path)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1,
    ) as process:
        yield HostDevice(process)
