"""Stage-1 bootstrap: prove the mock is protocol-faithful using tinytuya itself.

A real tinytuya client connects to the loopback mock, performs the full
handshake for its protocol version, and reads status().  If these pass, the
mock is confirmed as ground truth and can be used to validate *other* clients
(in any language).

The matrix covers every supported version (v3.1-v3.5) plus the ``device22``
quirk on the versions where the tinytuya client actually auto-detects it
(v3.3/v3.4).
"""

import contextlib
import json
import subprocess
import sys

import pytest
import tinytuya

LOCAL_KEY = "thisisarealkey00"
DEV_ID = "eb0123456789abcdefghij"
ALL_VERSIONS = ["3.1", "3.2", "3.3", "3.4", "3.5"]


@contextlib.contextmanager
def spawn_mock(version="3.5", local_key=LOCAL_KEY, dps=None, dev22=False,
               extra_args=(), max_connections=None):
    """Start ``python -m tuyamock`` on an OS-assigned port; yield (port, proc)."""
    args = [
        sys.executable, "-m", "tuyamock",
        "--version", version,
        "--port", "0",
        "--local-key", local_key,
    ]
    if dps is not None:
        args += ["--dps", json.dumps(dps)]
    if dev22:
        args += ["--dev22"]
    if max_connections is not None:
        args += ["--max-connections", str(max_connections)]
    args += list(extra_args)

    proc = subprocess.Popen(
        args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    try:
        line = proc.stdout.readline()
        if not line:
            raise RuntimeError(
                "mock did not print a port; stderr:\n" + proc.stderr.read()
            )
        port = int(line.strip())
        yield port, proc
    finally:
        if proc.poll() is None:
            proc.terminate()
        with contextlib.suppress(subprocess.TimeoutExpired):
            proc.wait(timeout=5)
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5)


def make_client(port, version="3.5", local_key=LOCAL_KEY):
    # A couple of retries so a slow accept under load doesn't fail the test,
    # but few/short enough that a real protocol regression still fails fast.
    dev = tinytuya.Device(
        DEV_ID, address="127.0.0.1", local_key=local_key, version=float(version),
        port=port, connection_retry_limit=3, connection_retry_delay=1,
    )
    dev.set_socketTimeout(5)
    return dev


# --------------------------------------------------------------------------
# core matrix
# --------------------------------------------------------------------------

@pytest.mark.parametrize("version", ALL_VERSIONS)
def test_handshake_and_status(version):
    """A tinytuya client of each version completes its handshake and reads dps."""
    with spawn_mock(version=version) as (port, _proc):
        status = make_client(port, version).status()

        assert status is not None, "status() returned None"
        assert "Err" not in status, status
        assert "dps" in status, status
        assert status["dps"]["21"] == "white"
        assert status["dps"]["22"] == 946


@pytest.mark.parametrize("version", ALL_VERSIONS)
def test_stateful_set_and_status(version):
    """set_value/set_multiple_values/turn_on/off mutate shared state that a
    later status() reflects — the mock is a stateful device, not a fixed reply."""
    with spawn_mock(version=version, dps={"1": False, "20": "white", "22": 100}) as (port, _p):
        d = make_client(port, version)

        # A set reports back the changed dp...
        r = d.set_value("1", True)
        assert isinstance(r, dict) and r.get("dps") == {"1": True}, r
        # ...and persists across the (non-persistent) reconnect.
        assert d.status()["dps"]["1"] is True

        # Multiple values at once.
        d.set_multiple_values({"20": "red", "22": 255})
        dps = d.status()["dps"]
        assert dps["20"] == "red" and dps["22"] == 255 and dps["1"] is True

        # turn_off / turn_on map to set_status on switch 1.
        d.turn_off(1)
        assert d.status()["dps"]["1"] is False
        d.turn_on(1)
        assert d.status()["dps"]["1"] is True


@pytest.mark.parametrize("version", ALL_VERSIONS)
def test_updatedps_and_heartbeat(version):
    """updatedps() reports the requested dps; heartbeat() returns an empty ack."""
    with spawn_mock(version=version, dps={"1": True, "20": "white"}) as (port, _p):
        d = make_client(port, version)
        r = d.updatedps([20])
        assert isinstance(r, dict) and r.get("dps") == {"20": "white"}, r
        # Devices answer a heartbeat with an empty payload (decodes to None).
        assert d.heartbeat(nowait=False) is None


def test_clean_shutdown_single_connection():
    """`--max-connections 1` exits cleanly (code 0) after one client closes."""
    with spawn_mock(version="3.5", max_connections=1) as (port, proc):
        status = make_client(port, "3.5").status()
        assert status["dps"]["21"] == "white"
        assert proc.wait(timeout=5) == 0


@pytest.mark.parametrize("version", ALL_VERSIONS)
def test_custom_dps_injection(version):
    """Data points are injectable via the CLI (no hard-coded values)."""
    custom = {"1": True, "2": 50, "3": "scene_4"}
    with spawn_mock(version=version, dps=custom) as (port, _proc):
        status = make_client(port, version).status()
        assert status["dps"] == custom


@pytest.mark.parametrize("version", ["3.3", "3.4"])
def test_device22_quirk(version):
    """device22 rejects the standard query; client retries via CONTROL_NEW.

    A real device22 returns ONLY the requested dps. We seed dp "99" (which the
    client never asks for) to prove the mock returns a subset, not the full set
    — this would have caught the bug where --dev22 was a silent no-op on v3.4.
    """
    with spawn_mock(version=version, dev22=True, dps={"1": "on", "99": "x"}) as (port, _p):
        client = make_client(port, version)
        status = client.status()
        assert status is not None and "dps" in status, status
        assert client.dev_type == "device22", "client did not detect device22"
        assert status["dps"] == {"1": "on"}, status  # subset only, not {"1","99"}


@pytest.mark.parametrize("version", ["3.3", "3.4"])
def test_device22_stateful_set(version):
    """set_value works in device22 mode and the value persists.

    device22 status() only returns the dps the client explicitly requests, so we
    prove persistence two ways: dp "1" (always requested after detection) round
    trips, and dp "20" comes back once we add it to the request set.
    """
    with spawn_mock(version=version, dev22=True, dps={"1": False, "20": "white"}) as (port, _p):
        d = make_client(port, version)

        d.status()                                     # triggers device22 detection
        assert d.dev_type == "device22"
        assert d.set_value("1", True)["dps"] == {"1": True}
        assert d.status()["dps"]["1"] is True          # dp 1 is always requested

        d.set_value("20", "red")
        d.set_dpsUsed({"1": None, "20": None})         # ask for dp 20 too
        assert d.status()["dps"]["20"] == "red"        # it was persisted


def test_device22_auto_on_v32():
    """A v3.2 client always drives the device22 dialect (no --dev22 needed)."""
    with spawn_mock(version="3.2", dps={"1": "on", "20": "white"}) as (port, _p):
        client = make_client(port, "3.2")
        status = client.status()
        assert client.dev_type == "device22"
        assert status["dps"]["20"] == "white"


@pytest.mark.parametrize("version", ["3.1", "3.5"])
def test_device22_rejected_on_unsupported_versions(version):
    """--dev22 on v3.1/v3.5 is rejected: the tinytuya client cannot recover."""
    proc = subprocess.Popen(
        [sys.executable, "-m", "tuyamock", "--version", version, "--port", "0",
         "--local-key", LOCAL_KEY, "--dev22"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    out, err = proc.communicate(timeout=10)
    assert proc.returncode != 0, "expected non-zero exit"
    assert out.strip() == "", "should not have printed a port"
    assert "device22" in err.lower()


# --------------------------------------------------------------------------
# harness / robustness
# --------------------------------------------------------------------------

def test_port_zero_prints_real_port():
    """`--port 0` must bind a real port and announce it on stdout."""
    with spawn_mock(max_connections=None) as (port, _proc):
        assert 1024 <= port <= 65535


def test_wrong_key_fails_handshake():
    """A client with the wrong local key must NOT get valid status.

    Guards against the mock accidentally accepting any key (which would make it
    a useless oracle).
    """
    with spawn_mock(version="3.5") as (port, _proc):
        status = make_client(port, "3.5", local_key="wrongkeywrongk00").status()
        assert (status is None) or ("dps" not in status), status


def test_parallel_instances_are_isolated():
    """Two mocks on independent ports serve their own dps simultaneously."""
    with spawn_mock(dps={"21": "red", "22": 1}) as (port_a, _a), \
         spawn_mock(dps={"21": "blue", "22": 2}) as (port_b, _b):
        assert port_a != port_b
        assert make_client(port_a).status()["dps"]["21"] == "red"
        assert make_client(port_b).status()["dps"]["21"] == "blue"


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
