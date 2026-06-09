"""In-process API tests: drive the mock with tinytuya from one process.

These exercise tuyamock.MockDevice (background-thread server) rather than
spawning ``python -m tuyamock``, and explicitly verify the device22
reject -> reconnect mechanism.
"""

import contextlib
import os
import resource
import socket

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


def test_fleet_scales_past_fd_1024():
    """A fleet of mocks in one process, each with a live v3.4 handshake, must all
    work even though their socket fds climb well past 1024. This is the at-scale
    guard for the select(2) FD_SETSIZE bug (a select()-based loop silently killed
    the serve thread of any instance landing on a high fd). Each mock carries a
    unique dp, so a correct reply proves the client reached the right device.

    256 is enough to push fds past 1024 without the cost of a 1000-OS-thread
    fleet (that scales fine too — teardown is O(1) via the wake pipe — but in one
    process it is a thread-per-mock pattern; real fleets use separate processes).
    Raises its own fd soft limit (CI often defaults to 1024); skips if the hard
    limit cannot accommodate it. Override the size with TUYAMOCK_FLEET_N."""
    n = int(os.environ.get("TUYAMOCK_FLEET_N", "256"))
    need = 6 * n + 256  # listen + wake-pair + accepted + client-side, with slack
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    if hard != resource.RLIM_INFINITY and hard < need:
        pytest.skip("RLIMIT_NOFILE hard=%d < %d needed for a fleet of %d" % (hard, need, n))
    if soft != resource.RLIM_INFINITY and soft < need:
        resource.setrlimit(resource.RLIMIT_NOFILE, (need, hard))

    mocks, clients = [], []
    try:
        for i in range(n):
            # idle_timeout=0 keeps every connection open so the fds accumulate.
            m = tuyamock.MockDevice(local_key=KEY, version="3.4",
                                    dps={"1": True, "n": i}, idle_timeout=0)
            m.start()
            mocks.append(m)
            d = tinytuya.Device(DEV_ID, "127.0.0.1", KEY, version=3.4, port=m.port,
                                persist=True, connection_retry_limit=1,
                                connection_retry_delay=1)
            d.set_socketTimeout(3)
            clients.append(d)
            status = d.status()
            assert isinstance(status, dict) and status.get("dps", {}).get("n") == i, (
                "mock #%d handshake/status failed: %r" % (i, status))

        # We genuinely crossed the fd 1024 boundary and no serve thread died.
        assert max(m.server._srv.fileno() for m in mocks) >= 1024
        assert all(m._thread.is_alive() for m in mocks)
    finally:
        for d in clients:
            with contextlib.suppress(Exception):
                d.close()
        for m in mocks:
            with contextlib.suppress(Exception):
                m.stop()


def test_high_fd_socket_does_not_break_serve_loop():
    """A mock whose sockets land at fd >= 1024 must still work, including the v3.4
    handshake. select(2) cannot watch an fd >= FD_SETSIZE (1024) and raises
    ValueError, which silently killed the serve thread; the loop uses selectors
    (epoll/kqueue) instead. With a few hundred mocks in one process the fds climb
    past 1024, so this guards that whole regime. Skipped where the fd ceiling is
    too low to even reach fd 1024 (e.g. a constrained CI ulimit)."""
    soft, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
    if soft < 1100:
        pytest.skip("RLIMIT_NOFILE=%d too low to push fds past 1024" % soft)

    pad = []
    try:
        while not pad or pad[-1].fileno() < 1030:
            pad.append(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
        with tuyamock.MockDevice(local_key=KEY, version="3.4", dps={"1": True}) as mock:
            assert mock.server._srv.fileno() >= 1024  # listen socket is high
            d = client(mock.port, "3.4")
            assert d.status()["dps"]["1"] is True       # handshake survived
            d.set_value("1", False)
            assert mock.dps["1"] is False
            assert mock._thread.is_alive()              # serve thread did not die
    finally:
        for s in pad:
            s.close()


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
