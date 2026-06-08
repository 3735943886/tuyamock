"""In-process API tests: drive the mock with tinytuya from one process.

These exercise tuyamock.MockDevice (background-thread server) rather than
spawning ``python -m tuyamock``, and explicitly verify the device22
reject -> reconnect mechanism.
"""

import contextlib
import os

import pytest
import tinytuya

import tuyamock

KEY = "thisisarealkey00"
DEV_ID = "eb0123456789abcdefghij"
ALL_VERSIONS = ["3.1", "3.2", "3.3", "3.4", "3.5"]


@contextlib.contextmanager
def pinned_to_one_cpu():
    """Pin this process to a single CPU for the duration of the block.

    Tuya clients open a fresh TCP connection per command, so the mock's
    single-client select loop must hand off cleanly when one connection's EOF and
    the next connection's SYN arrive in the *same* select wake-up. That coalescing
    only happens when the server thread is starved of CPU, so we force it by
    pinning every thread to one core — this deterministically reproduces the
    reconnect-clobber race (pre-fix: nearly every iteration failed). Skips where
    affinity control is unavailable (e.g. macOS).
    """
    setaff = getattr(os, "sched_setaffinity", None)
    if setaff is None:
        pytest.skip("os.sched_setaffinity unavailable on this platform")
    original = os.sched_getaffinity(0)
    setaff(0, {next(iter(original))})
    try:
        yield
    finally:
        setaff(0, original)


def client(port, version):
    d = tinytuya.Device(DEV_ID, "127.0.0.1", KEY, version=float(version), port=port,
                        connection_retry_limit=3, connection_retry_delay=1)
    d.set_socketTimeout(5)
    return d


@pytest.mark.parametrize("version", ALL_VERSIONS)
def test_inprocess_status_and_set(version):
    with tuyamock.MockDevice(local_key=KEY, version=version,
                             dps={"1": True, "20": "white"}) as mock:
        d = client(mock.port, version)
        assert d.status()["dps"]["20"] == "white"
        d.set_value("20", "red")
        assert mock.dps["20"] == "red"        # live device state mutated
        assert d.status()["dps"]["20"] == "red"


@pytest.mark.parametrize("version", ["3.3", "3.4", "3.5"])
def test_rapid_reconnect_stress(version):
    """Hammer the per-command reconnect path to catch the single-client handoff race.

    Each status()/set_value() opens a fresh connection, so this exercises many
    close→reconnect cycles back-to-back. Pinned to one CPU (see helper) the old
    server clobbered a freshly-accepted connection when the previous one's EOF was
    serviced in the same select wake-up, surfacing as "session key negotiation
    failed" / Err 914 on the next command. Every cycle must round-trip cleanly.
    """
    with pinned_to_one_cpu():
        with tuyamock.MockDevice(local_key=KEY, version=version,
                                 dps={"1": True, "20": "white"}) as mock:
            d = client(mock.port, version)
            for i in range(25):
                colour = "red" if i % 2 else "white"
                d.set_value("20", colour)
                assert mock.dps["20"] == colour, (
                    "set lost on cycle %d (mock.dps=%r)" % (i, mock.dps)
                )
                assert d.status()["dps"]["20"] == colour, (
                    "status mismatch on cycle %d" % i
                )


def test_mockdevice_reports_bound_port():
    with tuyamock.MockDevice(local_key=KEY, version="3.5", port=0) as mock:
        assert 1024 <= mock.port <= 65535


@pytest.mark.parametrize("version", ["3.3", "3.4"])
def test_device22_reject_then_reconnect(version):
    """One status() on a device22 mock uses two connections: reject + reconnect.

    First the mock rejects the standard query with "json obj data unvalid";
    tinytuya detects device22, reconnects, and retries via CONTROL_NEW. Both
    halves must land on the mock for status() to return real data.
    """
    with tuyamock.MockDevice(local_key=KEY, version=version, dev22=True,
                             dps={"1": False}) as mock:
        d = client(mock.port, version)

        before = mock.server.connections
        status = d.status()
        used = mock.server.connections - before

        assert d.dev_type == "device22"          # detection happened
        assert status["dps"]["1"] is False       # reconnect delivered real data
        assert used == 2, "expected reject + reconnect, got %d connection(s)" % used

        # Normal operation continues afterwards.
        d.set_value("1", True)
        assert mock.dps["1"] is True
