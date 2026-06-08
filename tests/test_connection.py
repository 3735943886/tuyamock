"""Connection-lifecycle fidelity: seqno pairing, nowait sends, device push, idle timeout.

These cover behaviours a persistent/monitoring client depends on, verified
against the real tinytuya client.
"""

import time

import pytest
import tinytuya

import tuyamock

KEY = "thisisarealkey00"
DEV_ID = "eb0123456789abcdefghij"
ALL_VERSIONS = ["3.1", "3.2", "3.3", "3.4", "3.5"]


def client(port, version, persist=False, timeout=4):
    d = tinytuya.Device(DEV_ID, "127.0.0.1", KEY, version=float(version), port=port,
                        persist=persist, connection_retry_limit=2, connection_retry_delay=1)
    d.set_socketTimeout(timeout)
    return d


@pytest.mark.parametrize("version", ALL_VERSIONS)
def test_response_seqno_pairs_retcode(version):
    """tinytuya pairs a reply to its request by seqno (echoed for <3.5, global for
    3.5). If the mock used the wrong seqno, cmd_retcode would silently stay None."""
    with tuyamock.MockDevice(local_key=KEY, version=version, dps={"1": True}) as mock:
        d = client(mock.port, version)
        d.status()
        assert d.cmd_retcode == 0, "retcode not paired (seqno mismatch) on v%s" % version


def test_nowait_and_send_do_not_break_server():
    """A client that fires nowait/raw sends without reading the reply must not
    crash or wedge the mock (real devices reply regardless; the socket may close)."""
    with tuyamock.MockDevice(local_key=KEY, version="3.5", dps={"1": True}) as mock:
        d = client(mock.port, "3.5")
        d.set_value("1", False, nowait=True)            # send, never read response
        d.heartbeat(nowait=True)                        # fire-and-forget
        d.send(d.generate_payload(tinytuya.UPDATEDPS))  # raw send, no receive
        time.sleep(0.3)

        assert mock._thread.is_alive(), "server thread died on a nowait client"
        # The mock is still fully functional and the nowait set landed.
        assert client(mock.port, "3.5").status()["dps"]["1"] is False


@pytest.mark.parametrize("version", ["3.3", "3.5"])
def test_device_push_received_by_monitor(version):
    """A device-initiated push() reaches a monitoring client via receive()."""
    with tuyamock.MockDevice(local_key=KEY, version=version,
                             dps={"1": True, "20": "white"}) as mock:
        d = client(mock.port, version, persist=True)
        assert d.status()["dps"]["20"] == "white"

        assert mock.push({"20": "red"}) is True

        update = None
        for _ in range(5):
            update = d.receive()
            if isinstance(update, dict) and "dps" in update:
                break
        assert update is not None and update.get("dps", {}).get("20") == "red", update


def test_idle_timeout_drops_silent_connection():
    """A persistent connection with no inbound packets is dropped after the idle
    timeout — which is why real clients must send heartbeats. (We assert the drop
    server-side: tinytuya's persistent client does not cleanly re-handshake after
    a server-initiated close, so heartbeats, not reconnects, are the real fix.)"""
    with tuyamock.MockDevice(local_key=KEY, version="3.5", dps={"1": True},
                             idle_timeout=1.0) as mock:
        d = client(mock.port, "3.5", persist=True)
        d.status()
        assert mock.connected, "connection should be held open after status()"

        time.sleep(2.5)  # exceed idle_timeout without sending anything

        assert not mock.connected, "server did not drop the idle connection"


def test_heartbeat_keeps_connection_alive():
    """Heartbeats reset the idle timer, so a heartbeating client is NOT dropped."""
    with tuyamock.MockDevice(local_key=KEY, version="3.5", dps={"1": True},
                             idle_timeout=2.0) as mock:
        d = client(mock.port, "3.5", persist=True)
        d.status()

        for _ in range(4):
            time.sleep(0.8)            # < idle_timeout
            d.heartbeat(nowait=True)   # fire-and-forget keep-alive resets the timer

        assert mock.connected, "heartbeating client was dropped"
