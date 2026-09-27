#!/usr/bin/env python3
"""Verify the interop adapter contract without external peers or network I/O."""
import os
from pathlib import Path
import subprocess
import shutil
import tempfile

bash = shutil.which("bash")
assert bash is not None, "bash is required"
runner = Path(__file__).resolve().with_name("run-matrix.sh")
peers = ["quinn", "quiche", "ngtcp2", "s2n-quic", "msquic"]
with tempfile.TemporaryDirectory(prefix="quion-interop-contract-") as tmp:
    root = Path(tmp)
    log = root / "calls"
    for peer in peers:
        adapter = root / ("quion-interop-" + peer)
        adapter.write_text('#!/bin/sh\nprintf "%s %s\\n" "${0##*/}" "$*" >> "$QUION_MATRIX_LOG"\n')
        adapter.chmod(0o700)
    env = dict(os.environ, PATH=tmp, QUION_MATRIX_LOG=str(log))
    for early in ("0", "1"):
        log.write_text("")
        env["QUION_INTEROP_ZERO_RTT"] = early
        subprocess.run([bash, str(runner)], env=env, check=True, capture_output=True)
        scenarios = ["stream-transfer", "datagram", "retry", "version-negotiation", "close", "idle-timeout"]
        if early == "1":
            scenarios.append("zero-rtt")
        pairs = [("client-handshake", "client"), ("server-handshake", "server")]
        pairs += [(scenario, role) for scenario in scenarios for role in ("client", "server")]
        expected = [f"quion-interop-{peer} --scenario {scenario} --role {role}" for peer in peers for scenario, role in pairs]
        assert log.read_text().splitlines() == expected
    (root / "quion-interop-msquic").unlink()
    missing = subprocess.run([bash, str(runner)], env=env, capture_output=True)
    assert missing.returncode == 2
print("Interop contract passed: 70 default cases, 80 with 0-RTT; missing adapters fail closed.")
