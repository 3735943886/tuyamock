"""Device configuration, per-connection session state, and command dispatch.

The version-specific crypto/framing lives in :mod:`tuyamock.protocol`; this
module is the version-agnostic glue: it tracks per-connection nonces/keys and
maps decoded commands to responses.
"""

import json
import logging
import secrets
import time

# TINYTUYA-COUPLING (Layer 1: import linkage). Internal tinytuya modules; a rename/move
# in tinytuya breaks these imports loudly. See README "Dependence on tinytuya".
from tinytuya.core import command_types as CT
from tinytuya.core.exceptions import DecodeError
from tinytuya.core.message_helper import parse_header

from . import protocol

log = logging.getLogger(__name__)

SUPPORTED_VERSIONS = protocol.SUPPORTED_VERSIONS

# TINYTUYA-COUPLING (Layer 3: hand-mirrored client policy). Versions where the tinytuya
# client actually supports the device22 dialect. v3.2 is always device22; v3.3/v3.4
# auto-detect it from a rejected query. If tinytuya changes which versions it can
# recover device22 on, update this set (and the DeviceConfig rejection below).
DEV22_VERSIONS = ("3.2", "3.3", "3.4")

# Canned data points mirroring the original fake-v35-device.py example so the
# default mock looks like a plausible RGBCW bulb.
DEFAULT_DPS = {
    "20": True,
    "21": "white",
    "22": 946,
    "23": 3,
    "24": "014a03e803a9",
    "25": "04464602007803e803e800000000464602007803e8000a00000000",
    "26": 0,
    "34": False,
}

# TINYTUYA-COUPLING (Layer 3: hand-mirrored client policy). Exact error string a device
# returns when polled with the wrong query command; the tinytuya client matches on
# this literal to switch to the device22 dialect. If tinytuya changes the string it
# keys on, device22 detection breaks silently.
DATA_UNVALID = b"json obj data unvalid"


class DeviceConfig:
    """Static configuration of the emulated device (everything but per-connection state)."""

    def __init__(
        self,
        local_key,
        dps=None,
        version="3.5",
        gw_id="eb0123456789abcdefghij",
        product_key="keydeadbeef12345",
        dev22=False,
    ):
        if isinstance(local_key, str):
            local_key = local_key.encode("latin1")
        if len(local_key) != 16:
            raise ValueError(
                "local_key must be exactly 16 bytes, got %d (%r)"
                % (len(local_key), local_key)
            )
        self.profile = protocol.get_profile(version)  # validates version
        self.version = self.profile.version
        if dev22 and self.version not in DEV22_VERSIONS:
            # The tinytuya reference client only detects/handles device22 on
            # v3.2-v3.4 (v3.2 is forced into it). On v3.1/v3.5 a device22 reply
            # leaves the client unable to recover, so reject the combo loudly.
            raise ValueError(
                "device22 is only emulated for versions %s, not %s"
                % (", ".join(DEV22_VERSIONS), self.version)
            )
        self.real_key = local_key
        self.dps = dict(dps) if dps is not None else dict(DEFAULT_DPS)
        self.gw_id = gw_id
        self.product_key = product_key
        self.dev22 = dev22

    def discovery_payload(self, ip="127.0.0.1"):
        """The JSON a device broadcasts over UDP for discovery."""
        return json.dumps(
            {
                "ip": ip,
                "gwId": self.gw_id,
                "active": 2,
                "ablilty": 0,
                "encrypt": True,
                "productKey": self.product_key,
                "version": self.version,
                "token": True,
                "wf_cfg": True,
            }
        ).encode("utf8")


class Session:
    """Per-connection negotiation/cipher state for one client.

    A fresh ``Session`` is created for every accepted TCP connection because the
    session key (when used) is derived from per-connection nonces.
    """

    def __init__(self, config):
        self.config = config
        self.profile = config.profile
        self.real_key = config.real_key
        # The device's own nonce: 16 ASCII bytes, stable for the connection.
        self.local_nonce = secrets.token_hex(8).encode("ascii")
        self.remote_nonce = b""
        self.session_key = None
        # Key currently in force: starts as the real key (used for the handshake
        # and for session-less versions) and is swapped for the derived session
        # key once negotiation finishes - mirroring the tinytuya client, which
        # only switches *after* sending FINISH.
        self.key = config.real_key
        # The device's own global seqno counter, used for v3.5 command responses
        # and for device-initiated pushes on every version.
        self.seqno = 1
        # Seqno of the request currently being handled; v3.1-3.4 responses echo it
        # (tinytuya matches retcode on it for version < 3.5).
        self.req_seqno = 0

    def next_global_seqno(self):
        """Allocate the next device-global seqno (v3.5 responses, async pushes)."""
        s = self.seqno
        self.seqno += 1
        return s

    def session_nonce(self):
        """client_nonce XOR device_nonce (the basis for the session key)."""
        return bytes(a ^ b for a, b in zip(self.remote_nonce, self.local_nonce))

    # -- handshake --------------------------------------------------------

    def _handle_neg_start(self, msg):
        """SESS_KEY_NEG_START -> SESS_KEY_NEG_RESP: our nonce + HMAC over theirs."""
        self.remote_nonce = msg.payload
        reply = self.local_nonce + protocol.session_hmac(self.real_key, self.remote_nonce)
        wire = self.profile.negotiation_response(self, reply)
        return self.profile.pack_response(self, CT.SESS_KEY_NEG_RESP, wire)

    def _handle_neg_finish(self, msg):
        """SESS_KEY_NEG_FINISH -> derive + install the session key. No reply."""
        expected = protocol.session_hmac(self.real_key, self.local_nonce)
        if not secrets.compare_digest(expected, msg.payload):
            raise DecodeError("session key negotiation FINISH HMAC mismatch")
        self.session_key = self.profile.derive_session_key(self)
        self.key = self.session_key
        log.debug("session key established: %s", self.session_key.hex())
        return None

    # -- data plane -------------------------------------------------------

    def _status_response(self, cmd, only=None):
        dps = dict(self.config.dps)
        if only is not None:
            # device22 devices return only the data points that were asked for.
            dps = {k: dps[k] for k in only if k in dps}
        resp = {
            "protocol": 4,
            "t": int(time.time()),
            "data": {"dps": dps},
        }
        body = self.profile.encrypt_payload(self, json.dumps(resp).encode("ascii"))
        return self.profile.pack_response(self, cmd, body)

    def _error_response(self, cmd, text):
        body = self.profile.encrypt_payload(self, text)
        return self.profile.pack_response(self, cmd, body)

    def _parse_dps(self, msg):
        """Extract the dps dict from a CONTROL/CONTROL_NEW payload (both shapes)."""
        try:
            payload = json.loads(msg.payload.decode("utf8"))
        except (ValueError, AttributeError):
            log.warning("could not parse control payload: %r", msg.payload)
            return {}
        dps = payload.get("data", {}).get("dps")
        if dps is None:
            dps = payload.get("dps")
        return dps if isinstance(dps, dict) else {}

    def _handle_control(self, msg):
        """CONTROL/CONTROL_NEW: a *set* (concrete dps), or a device22 status poll.

        A set mutates the shared device state and reports back the changed dps,
        which is what real devices do and what a subsequent status() reflects.
        An all-null dps payload is a device22 status query.
        """
        dps = self._parse_dps(msg)
        sets = {str(k): v for k, v in dps.items() if v is not None}
        if sets:
            self.config.dps.update(sets)
            return self._status_response(msg.cmd, only=list(sets))
        # No concrete values: a status poll. device22 echoes only the requested
        # dps; an ordinary device (e.g. a v3.2 client polling via CONTROL_NEW)
        # returns everything.
        only = [str(k) for k in dps] if (self.config.dev22 and dps) else None
        return self._status_response(msg.cmd, only=only)

    def _handle_updatedps(self, msg):
        """UPDATEDPS: report the requested dpIds (refresh request)."""
        only = None
        try:
            payload = json.loads(msg.payload.decode("utf8"))
            ids = payload.get("dpId")
            if ids:
                only = [str(i) for i in ids]
        except (ValueError, AttributeError):
            log.warning("could not parse updatedps payload: %r", msg.payload)
        return self._status_response(msg.cmd, only=only)

    def status_push(self, dps=None):
        """Build an unsolicited STATUS frame (device-initiated update).

        Returns packed bytes to send to a connected client, or None if no session
        key is established yet. Used by the server's push() so a monitor-style
        client can ``receive()`` device-initiated changes. Async pushes use the
        device's global seqno on every version (there is no request to echo).
        """
        if self.profile.needs_session and self.session_key is None:
            return None
        reported = dict(self.config.dps) if dps is None else {str(k): v for k, v in dps.items()}
        resp = {"protocol": 4, "t": int(time.time()), "data": {"dps": reported}}
        body = self.profile.encrypt_payload(self, json.dumps(resp).encode("ascii"))
        return self.profile.pack_response(
            self, CT.STATUS, body, seqno=self.next_global_seqno()
        )

    def handle(self, msg):
        """Dispatch one decoded client message, returning packed reply bytes or None."""
        cmd = msg.cmd
        # v3.1-3.4 responses echo this; v3.5 ignores it (uses the global counter).
        self.req_seqno = msg.seqno
        if cmd == CT.SESS_KEY_NEG_START:
            return self._handle_neg_start(msg)
        if cmd == CT.SESS_KEY_NEG_FINISH:
            return self._handle_neg_finish(msg)

        if cmd in (CT.DP_QUERY, CT.DP_QUERY_NEW):
            # TINYTUYA-COUPLING (Layer 3: hand-mirrored client policy). The device22
            # reject->reconnect contract: which opcode is the "standard" status query
            # is version-dependent (DP_QUERY v3.1-3.3, DP_QUERY_NEW v3.4+), and we must
            # reject WHICHEVER applies so the tinytuya client detects device22 and
            # retries via CONTROL_NEW. This tracks XenonDevice behaviour, not a
            # tinytuya API; a client-side change here will NOT surface automatically.
            if self.config.dev22:
                return self._error_response(cmd, DATA_UNVALID)
            return self._status_response(cmd)

        if cmd in (CT.CONTROL, CT.CONTROL_NEW):
            return self._handle_control(msg)
        if cmd == CT.UPDATEDPS:
            return self._handle_updatedps(msg)
        if cmd == CT.HEART_BEAT:
            # Devices reply to a heartbeat with an empty payload.
            return self.profile.pack_response(self, CT.HEART_BEAT, b"")

        log.info("unhandled command 0x%02x", cmd)
        return self._error_response(cmd, DATA_UNVALID)


class TuyaMockDevice:
    """Front end: holds the static config and frames a byte stream into messages."""

    def __init__(self, config):
        self.config = config

    def new_session(self):
        return Session(self.config)

    def unpack(self, session, frame):
        return session.profile.unpack_request(session, frame)


def take_frames(buffer):
    """Split a TCP byte buffer into complete Tuya frames.

    Returns ``(frames, leftover)`` where ``frames`` is a list of complete frame
    byte-strings and ``leftover`` is the trailing partial frame still awaiting
    more bytes.  Robust to multiple frames per read and a frame split across
    reads.
    """
    frames = []
    offset = 0
    n = len(buffer)
    while n - offset >= 4:
        try:
            header = parse_header(buffer[offset:])
        except DecodeError:
            break  # not enough bytes to parse a header yet
        # TINYTUYA-COUPLING (Layer 2): we depend on parse_header().total_length covering
        # the WHOLE frame (prefix..suffix). If that attribute is renamed or its length
        # accounting changes, stream re-framing silently corrupts.
        end = offset + header.total_length
        if end > n:
            break  # full frame not yet received
        frames.append(buffer[offset:end])
        offset = end
    return frames, buffer[offset:]
