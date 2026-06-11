"""TCP server loop that drives :class:`TuyaMockDevice` over a real socket."""

import json
import logging
import selectors
import socket
import threading

# TINYTUYA-COUPLING (Layer 1: import linkage). Internal tinytuya modules + the top-level
# `tinytuya.udpkey`; a rename/move breaks these imports loudly. See README.
from tinytuya.core import command_types as CT
from tinytuya.core import header as H
from tinytuya.core.exceptions import DecodeError
from tinytuya.core.message_helper import TuyaMessage, pack_message, unpack_message

import tinytuya

from .device import DeviceConfig, TuyaMockDevice, take_frames

log = logging.getLogger(__name__)

# UDP discovery ports a real tinytuya scanner uses (tinytuya.core.const):
#   6667 (UDPPORTS)   — encrypted passive announce; we emit periodic beacons here.
#   7000 (UDPPORTAPP) — the app broadcasts REQ_DEVINFO here for v3.5 devices to
#                       answer; we bind it to reply to those active probes.
DISCOVERY_BEACON_PORT = 6667
DISCOVERY_PROBE_PORT = 7000


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
                 discovery_addr="127.0.0.1", idle_timeout=30.0, probe_reply=True):
        self.config = config
        self.host = host
        self.port = port
        self.discovery = discovery
        self.discovery_addr = discovery_addr
        # When discovery is on, also answer the scanner's *active* REQ_DEVINFO
        # probes on UDP 7000 (not just emit passive beacons) — this is how a real
        # tinytuya scanner finds v3.5 devices. On by default. We bind 7000 with
        # SO_REUSEPORT, the same option the tinytuya scanner sets on its own 7000
        # listener, so a same-host scanner and the mock coexist (verified). Set
        # False to skip the 7000 bind entirely (passive beacon still works).
        self.probe_reply = probe_reply
        # Real Tuya devices drop a local TCP connection after ~30s with no inbound
        # packet (this is why clients send heartbeats). Set to 0/None to disable.
        self.idle_timeout = idle_timeout
        self.device = TuyaMockDevice(config)
        self._srv = None
        self._udp = None
        self._udp_listening = False  # whether _udp is bound to receive probes
        self._bcast_next = 0.0
        self._closed = False
        self.connections = 0  # total client connections accepted (observable)
        # Current connection, shared with push() (other thread); guarded by the lock.
        self._io_lock = threading.Lock()
        self._client = None
        self._session = None
        # Self-pipe so close() can wake the serve loop instantly from another
        # thread (rather than waiting out the select timeout). Without this, tearing
        # down a fleet of N mocks costs ~N seconds. Created in start().
        self._wake_r = None
        self._wake_w = None

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
        # Wakeup pipe (a socketpair, which the selector can watch portably).
        self._wake_r, self._wake_w = socket.socketpair()
        self._wake_r.setblocking(False)
        if self.discovery:
            self._udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._udp.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            self._udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if hasattr(socket, "SO_REUSEPORT"):
                self._udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            # Bind the app discovery port so we can RECEIVE the scanner's active
            # REQ_DEVINFO probes (all versions answer; see _handle_probe). Only when
            # probe_reply is on, since holding 7000 conflicts with a same-host
            # scanner. Best-effort: an unbound socket still sends passive beacons, so
            # if 7000 is taken we just skip the active path and stay discoverable.
            if self.probe_reply:
                try:
                    # Bind to self.host (not "") so passive beacons are *sourced*
                    # from this device's IP — the scanner keys discovered devices by
                    # the packet source address, so distinct hosts (e.g. 127.0.0.1,
                    # 127.0.0.2, … for a multi-device demo) show up as distinct
                    # devices. Use "0.0.0.0" as host to receive broadcast probes on a
                    # real LAN.
                    self._udp.bind((self.host, DISCOVERY_PROBE_PORT))
                    self._udp_listening = True
                except OSError as exc:
                    log.debug("could not bind UDP probe port %d, active probe reply "
                              "disabled: %s", DISCOVERY_PROBE_PORT, exc)
        log.info("listening on %s:%d (v%s)", self.host, self.port, self.config.version)
        return self.port

    @property
    def has_client(self):
        """Whether a client connection is currently held open."""
        return self._client is not None

    def close(self):
        if self._closed:
            return
        self._closed = True
        # Wake the serve loop immediately so its thread exits without waiting out
        # the select timeout (fast fleet teardown). We only SEND here; the wake
        # sockets are closed by serve_forever's finally, so the byte stays readable
        # until the loop drains it (closing _wake_r here would race the read and,
        # with an indefinite timeout, hang the thread).
        if self._wake_w is not None:
            try:
                self._wake_w.send(b"x")
            except OSError:
                pass
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

    # -- discovery (passive beacon + active probe reply) ------------------

    def _device_info_packet(self):
        """Frame this device's discovery JSON the way a real device announces it.

        Always 6699 + ``tinytuya.udpkey`` HMAC, regardless of the device's own
        protocol version — that is the on-wire form a tinytuya scanner decodes
        (`decrypt_udp`), and the per-version distinction lives in the ``version``
        field of the JSON payload, not the UDP framing. So one packet shape serves
        v3.1-v3.5; the scanner reports each at its advertised version.
        """
        payload = self.config.discovery_payload(ip=self.discovery_addr)
        # TINYTUYA-COUPLING (Layer 2): positional TuyaMessage build (field order) +
        # HMAC-framed with tinytuya.udpkey. If the well-known udpkey changes or
        # TuyaMessage's fields reorder, the packet silently stops being decodable by
        # a real tinytuya scanner.
        msg = TuyaMessage(
            1, CT.UDP_NEW, 0, payload, 0, True, H.PREFIX_6699_VALUE, True
        )
        return pack_message(msg, hmac_key=tinytuya.udpkey)

    def _maybe_broadcast(self, now):
        """Emit the periodic passive discovery beacon (every 8s)."""
        if not self.discovery or self._udp is None or now < self._bcast_next:
            return
        self._bcast_next = now + 8
        try:
            self._udp.sendto(self._device_info_packet(),
                             (self.discovery_addr, DISCOVERY_BEACON_PORT))
        except OSError as exc:
            log.debug("discovery broadcast failed: %s", exc)

    def _handle_probe(self):
        """Answer a scanner's active REQ_DEVINFO probe with this device's info.

        The app broadcasts ``REQ_DEVINFO`` (0x25) to port 7000; a device replies
        with its discovery JSON. We answer for every version (3.1-3.5): the reply's
        framing is version-agnostic and the scanner reads the version out of the
        payload. We reply to the app's IP (taken from the probe's ``ip`` field,
        falling back to the UDP source) on the app discovery port, where the
        scanner listens.
        """
        try:
            data, addr = self._udp.recvfrom(4048)
        except (OSError, ValueError):
            # Socket closed under us during teardown (fileno() -> -1).
            return
        try:
            msg = unpack_message(data, hmac_key=tinytuya.udpkey, no_retcode=None)
        except Exception:  # noqa: BLE001 - ignore undecodable/garbage UDP traffic
            return
        if msg.cmd != CT.REQ_DEVINFO:
            return  # not a discovery probe (e.g. another device's announce)
        app_ip = addr[0]
        try:
            app_ip = json.loads(msg.payload.decode()).get("ip") or app_ip
        except (ValueError, AttributeError):
            pass
        try:
            self._udp.sendto(self._device_info_packet(),
                             (app_ip, DISCOVERY_PROBE_PORT))
        except OSError as exc:
            log.debug("probe reply failed: %s", exc)

    # -- main loop --------------------------------------------------------

    def serve_forever(self, max_connections=None):
        """Accept and service clients until closed or ``max_connections`` served.

        Returns the number of connections fully handled.  Designed to be run in
        the main thread so SIGINT/SIGTERM (raised as KeyboardInterrupt by the
        CLI's signal handler) cleanly unwinds out of the event wait.

        Uses ``selectors`` (epoll/kqueue), NOT ``select.select()``, on purpose:
        select(2) cannot watch a socket whose fd number is >= 1024 (FD_SETSIZE)
        and raises ValueError. With a few hundred mock instances in one process
        the fd numbers climb past 1024, so a select()-based loop silently dies for
        every instance whose socket lands on a high fd (confirmed: a v3.4 mock at
        fd 1023 loses its handshake and its serve thread exits). epoll/kqueue have
        no such limit.
        """
        import time

        sel = selectors.DefaultSelector()
        sel.register(self._srv, selectors.EVENT_READ)
        sel.register(self._wake_r, selectors.EVENT_READ)
        if self._udp is not None and self._udp_listening:
            sel.register(self._udp, selectors.EVENT_READ)

        served = 0
        client = None
        session = None
        buffer = b""
        last_rx = 0.0          # time of last inbound packet, for the idle timeout
        client_registered = False

        def drop_client():
            nonlocal client, session, buffer, client_registered
            if client is None:
                return
            if client_registered:
                try:
                    sel.unregister(client)
                except (KeyError, ValueError, OSError):
                    pass
                client_registered = False
            try:
                client.close()
            except OSError:
                pass
            client = None
            session = None
            buffer = b""
            self._set_current(None, None)

        try:
            while not self._closed:
                # Sleep until something actually happens. close() wakes us via the
                # self-pipe, new connections wake us via the listen socket; we only
                # need a timeout for the time-based work (idle expiry, discovery),
                # so an otherwise-idle mock costs no CPU even in a fleet of 1000s.
                if self.discovery:
                    timeout = 1.0
                elif client is not None and self.idle_timeout:
                    timeout = max(0.05, self.idle_timeout - (time.time() - last_rx))
                else:
                    timeout = None
                try:
                    events = sel.select(timeout)
                except (OSError, ValueError):
                    # A registered socket was closed under us (e.g. close() from
                    # another thread to stop a background server).
                    break
                ready = {key.fileobj for key, _ in events}

                if self._wake_r in ready:
                    # close() poked us; drain and let the while-condition exit.
                    try:
                        self._wake_r.recv(4096)
                    except OSError:
                        pass
                    if self._closed:
                        break

                now = time.time()
                self._maybe_broadcast(now)

                # Answer the scanner's active REQ_DEVINFO probe (all versions).
                if self._udp is not None and self._udp in ready:
                    self._handle_probe()

                # Idle timeout: a real device drops the connection if it does not
                # receive a packet for ~30s (hence client heartbeats).
                if (client is not None and self.idle_timeout
                        and now - last_rx > self.idle_timeout):
                    log.info("client idle for >%.0fs, closing", self.idle_timeout)
                    drop_client()
                    served += 1
                    if max_connections is not None and served >= max_connections:
                        return served
                    continue

                # Service the existing client's data/disconnect BEFORE accepting a
                # new connection. Tuya clients are non-persistent (a fresh connection
                # per command), so one can close a connection and open the next so
                # fast that the old socket's EOF and the new SYN land in the *same*
                # wake-up. If we accepted first, the subsequent EOF handler would run
                # against the just-reassigned `client` and close the brand-new
                # socket, killing it before its handshake is read.
                if client is not None and client in ready:
                    try:
                        data = client.recv(4096)
                    except (ConnectionResetError, OSError):
                        data = b""

                    if not data:
                        drop_client()
                        served += 1
                        log.info("client disconnected (%d served)", served)
                        if max_connections is not None and served >= max_connections:
                            return served
                    else:
                        last_rx = now
                        buffer += data
                        frames, buffer = take_frames(buffer)
                        for frame in frames:
                            self._handle_frame(client, session, frame)

                if self._srv in ready and not self._closed:
                    try:
                        new_client, addr = self._srv.accept()
                    except OSError:
                        # Listen socket closed from another thread (stop()).
                        break
                    if client is not None:
                        # Previous client never sent EOF (abnormal for a synchronous
                        # client); replace it.
                        drop_client()
                    client = new_client
                    # A send timeout keeps a non-reading client (which never drains
                    # our responses) from blocking the loop forever in sendall; the
                    # blocked send raises and we drop the connection. recv is guarded
                    # by the selector so it never hits this.
                    client.settimeout(self.idle_timeout or None)
                    sel.register(client, selectors.EVENT_READ)
                    client_registered = True
                    buffer = b""
                    session = self.device.new_session()
                    last_rx = now
                    self._set_current(client, session)
                    self.connections += 1
                    log.info("client connected: %r", addr)
        except KeyboardInterrupt:
            log.info("interrupted, shutting down")
        finally:
            drop_client()
            try:
                sel.close()
            except Exception:  # noqa: BLE001 - best-effort cleanup
                pass
            self.close()
        return served

    def _set_current(self, client, session):
        """Publish the active connection so push() (another thread) can use it."""
        with self._io_lock:
            self._client = client
            self._session = session

    def _handle_frame(self, client, session, frame):
        try:
            msg = self.device.unpack(session, frame)
        except (DecodeError, Exception) as exc:  # noqa: BLE001 - never crash on bad input
            log.warning("failed to decode frame (%d bytes): %s", len(frame), exc)
            return
        log.debug("recv cmd=0x%02x payload=%r", msg.cmd, msg.payload)
        # Hold the I/O lock across handle()+sendall so a concurrent push() (other
        # thread) cannot interleave bytes on the socket or race on session.seqno.
        with self._io_lock:
            reply = session.handle(msg)
            if reply is not None:
                try:
                    client.sendall(reply)
                except OSError as exc:
                    # Client went away mid-exchange (e.g. a nowait command that
                    # sends without reading, then closes). Not fatal: the next
                    # recv/idle-check tears the connection down.
                    log.debug("send failed, client likely gone: %s", exc)

    def push(self, dps=None):
        """Send an unsolicited STATUS update to the currently-connected client.

        Emulates a device-initiated state report (what a monitor-style client
        ``receive()``s). ``dps`` defaults to the full current state; pass a dict to
        report only specific data points. Returns True if a frame was sent, False
        if there is no ready connection. Thread-safe; call it from any thread.
        """
        with self._io_lock:
            client, session = self._client, self._session
            if client is None or session is None:
                return False
            frame = session.status_push(dps)
            if frame is None:
                return False
            try:
                client.sendall(frame)
                return True
            except OSError as exc:
                log.debug("push failed, client likely gone: %s", exc)
                return False


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
                 discovery_addr="127.0.0.1", idle_timeout=30.0,
                 seqno_mode="faithful", probe_reply=True):
        self.config = DeviceConfig(
            local_key=local_key, dps=dps, version=version, dev22=dev22,
            gw_id=gw_id, product_key=product_key, seqno_mode=seqno_mode,
        )
        self.server = TuyaMockServer(
            self.config, host=host, port=port,
            discovery=discovery, discovery_addr=discovery_addr,
            idle_timeout=idle_timeout, probe_reply=probe_reply,
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

    @property
    def connected(self):
        """Whether a client connection is currently held open."""
        return self.server.has_client

    def push(self, dps=None):
        """Push a device-initiated STATUS update to the connected client.

        Lets a test simulate an asynchronous device update that a monitoring
        client picks up via ``receive()``. Returns True if sent.
        """
        return self.server.push(dps)

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
