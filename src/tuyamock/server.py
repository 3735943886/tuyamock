"""TCP server loop that drives :class:`TuyaMockDevice` over a real socket."""

import logging
import select
import socket
import threading

# TINYTUYA-COUPLING (Layer 1: import linkage). Internal tinytuya modules + the top-level
# `tinytuya.udpkey`; a rename/move breaks these imports loudly. See README.
from tinytuya.core import command_types as CT
from tinytuya.core import header as H
from tinytuya.core.exceptions import DecodeError
from tinytuya.core.message_helper import TuyaMessage, pack_message

import tinytuya

from .device import DeviceConfig, TuyaMockDevice, take_frames

log = logging.getLogger(__name__)


class TuyaMockServer:
    """Single-client TCP server emulating one Tuya device.

    Serving exactly ONE connection at a time is protocol-faithful, NOT a
    limitation: a real Tuya device handles a single local TCP connection and does
    not support concurrent local connections (a new connection supersedes the
    prior one). Clients therefore talk to it serially, opening a fresh connection
    per command. Do not "add multi-client support" — that would make the mock
    behave unlike real hardware. (The per-command reconnect handoff is the race the
    serve_forever loop is careful about; see test_rapid_reconnect_stress.)

    Binds IPv4 (avoiding the original example's AF_INET6 dual-stack trap, which
    makes ``127.0.0.1`` connects flaky), supports ``port=0`` for OS-assigned
    ports, and serves one client connection at a time.
    """

    def __init__(self, config, host="127.0.0.1", port=6668, discovery=False,
                 discovery_addr="127.0.0.1"):
        self.config = config
        self.host = host
        self.port = port
        self.discovery = discovery
        self.discovery_addr = discovery_addr
        self.device = TuyaMockDevice(config)
        self._srv = None
        self._udp = None
        self._bcast_next = 0.0
        self._closed = False
        self.connections = 0  # total client connections accepted (observable)

    # -- lifecycle --------------------------------------------------------

    def start(self):
        """Bind and listen.  Returns the actual bound port (resolves port 0)."""
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.host, self.port))
        # Small backlog so rapid sequential reconnects (a non-persistent client
        # firing several commands back-to-back) don't get refused mid-accept.
        srv.listen(8)
        self._srv = srv
        self.port = srv.getsockname()[1]
        if self.discovery:
            self._udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._udp.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        log.info("listening on %s:%d (v%s)", self.host, self.port, self.config.version)
        return self.port

    def close(self):
        if self._closed:
            return
        self._closed = True
        for sock in (self._srv, self._udp):
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *exc):
        self.close()

    # -- discovery beacon -------------------------------------------------

    def _maybe_broadcast(self, now):
        if not self.discovery or self._udp is None or now < self._bcast_next:
            return
        self._bcast_next = now + 8
        payload = self.config.discovery_payload(ip=self.discovery_addr)
        # TINYTUYA-COUPLING (Layer 2): positional TuyaMessage build (field order) +
        # the discovery beacon is HMAC-framed with tinytuya.udpkey. If the well-known
        # udpkey changes or TuyaMessage's fields reorder, the beacon silently won't be
        # decodable by a real tinytuya scanner.
        msg = TuyaMessage(
            1, CT.UDP_NEW, 0, payload, 0, True, H.PREFIX_6699_VALUE, True
        )
        data = pack_message(msg, hmac_key=tinytuya.udpkey)
        try:
            self._udp.sendto(data, (self.discovery_addr, 6667))
        except OSError as exc:
            log.debug("discovery broadcast failed: %s", exc)

    # -- main loop --------------------------------------------------------

    def serve_forever(self, max_connections=None):
        """Accept and service clients until closed or ``max_connections`` served.

        Returns the number of connections fully handled.  Designed to be run in
        the main thread so SIGINT/SIGTERM (raised as KeyboardInterrupt by the
        CLI's signal handler) cleanly unwinds out of ``select``.
        """
        import time

        served = 0
        client = None
        buffer = b""
        session = None
        try:
            while not self._closed:
                rlist = [self._srv]
                if client is not None:
                    rlist.append(client)
                try:
                    readable, _, _ = select.select(rlist, [], [], 1.0)
                except (OSError, ValueError):
                    # A socket was closed under us (e.g. close() called from
                    # another thread to stop a background server).
                    break

                self._maybe_broadcast(time.time())

                # Service the existing client's data/disconnect BEFORE accepting a
                # new connection. Tuya clients are non-persistent (a fresh connection
                # per command), so one can close a connection and open the next so
                # fast that the old socket's EOF and the new SYN land in the *same*
                # select wake-up. If we accepted first, the subsequent EOF handler
                # would run against the just-reassigned `client` and close the
                # brand-new socket, killing it before its handshake is read. We also
                # operate on the specific socket, not the mutable `client`, to keep
                # the two connections from being confused.
                if client is not None and client in readable:
                    try:
                        data = client.recv(4096)
                    except (ConnectionResetError, OSError):
                        data = b""

                    if not data:
                        client.close()
                        client = None
                        session = None
                        served += 1
                        log.info("client disconnected (%d served)", served)
                        if max_connections is not None and served >= max_connections:
                            return served
                    else:
                        buffer += data
                        frames, buffer = take_frames(buffer)
                        for frame in frames:
                            self._handle_frame(client, session, frame)

                if self._srv in readable and not self._closed:
                    try:
                        new_client, addr = self._srv.accept()
                    except OSError:
                        # Listen socket closed from another thread (stop()).
                        break
                    if client is not None:
                        # Previous client never sent EOF (abnormal for a synchronous
                        # client); replace it.
                        client.close()
                    client = new_client
                    client.setblocking(True)
                    buffer = b""
                    session = self.device.new_session()
                    self.connections += 1
                    log.info("client connected: %r", addr)
        except KeyboardInterrupt:
            log.info("interrupted, shutting down")
        finally:
            if client is not None:
                try:
                    client.close()
                except OSError:
                    pass
            self.close()
        return served

    def _handle_frame(self, client, session, frame):
        try:
            msg = self.device.unpack(session, frame)
        except (DecodeError, Exception) as exc:  # noqa: BLE001 - never crash on bad input
            log.warning("failed to decode frame (%d bytes): %s", len(frame), exc)
            return
        log.debug("recv cmd=0x%02x payload=%r", msg.cmd, msg.payload)
        reply = session.handle(msg)
        if reply is not None:
            client.sendall(reply)


class MockDevice:
    """Run a Tuya mock device in a background thread for in-process testing.

    Lets you spin up a mock and point a tinytuya client at it from a single
    Python file, no subprocess required::

        import tuyamock, tinytuya

        with tuyamock.MockDevice(local_key="thisisarealkey00", version="3.5",
                                 dps={"1": True}) as mock:
            d = tinytuya.Device("01234567890123456789", "127.0.0.1",
                                "thisisarealkey00", version=3.5, port=mock.port)
            print(d.status())            # -> {"dps": {"1": True}, ...}
            d.set_value("1", False)
            print(mock.dps)              # -> {"1": False}  (live device state)

    Or manage the lifecycle manually with :meth:`start` / :meth:`stop`.
    """

    def __init__(self, local_key, version="3.5", dps=None, dev22=False,
                 host="127.0.0.1", port=0, gw_id="eb0123456789abcdefghij",
                 product_key="keydeadbeef12345", discovery=False,
                 discovery_addr="127.0.0.1"):
        self.config = DeviceConfig(
            local_key=local_key, dps=dps, version=version, dev22=dev22,
            gw_id=gw_id, product_key=product_key,
        )
        self.server = TuyaMockServer(
            self.config, host=host, port=port,
            discovery=discovery, discovery_addr=discovery_addr,
        )
        self._thread = None

    @property
    def port(self):
        """The bound TCP port (valid after :meth:`start`)."""
        return self.server.port

    @property
    def dps(self):
        """Live device data-point state (mutated by client set commands)."""
        return self.config.dps

    def start(self):
        """Bind and start serving in a daemon thread. Returns the bound port."""
        port = self.server.start()
        self._thread = threading.Thread(
            target=self.server.serve_forever, name="tuyamock", daemon=True
        )
        self._thread.start()
        return port

    def stop(self):
        """Stop the server and join the background thread."""
        self.server.close()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *exc):
        self.stop()
