"""Per-version Tuya protocol profiles + shared crypto/framing utilities.

The device side of every protocol version is the *mirror image* of the client
logic in ``tinytuya.core.XenonDevice``.  Rather than scatter ``if version ==``
branches across the server, each version is captured by a small
:class:`VersionProfile` that knows how to:

* frame/unframe wire bytes (55AA-CRC, 55AA-HMAC, or 6699-GCM),
* encrypt/decrypt the inner payload (plaintext, v3.1 md5+ECB, ECB, or GCM),
* run the session-key handshake (none, ECB-derived, or GCM-derived).

Everything reuses tinytuya's own ``pack_message`` / ``unpack_message`` /
``AESCipher`` so the bytes on the wire are byte-identical to a real device.
"""

import hmac
import struct
from hashlib import md5, sha256

# TINYTUYA-COUPLING (Layer 1: import linkage). These are *internal* tinytuya modules,
# not a stable public API. A rename/move in tinytuya breaks the import loudly here
# (easy to fix). See README "Dependence on tinytuya".
from tinytuya.core import command_types as CT
from tinytuya.core import header as H
from tinytuya.core.crypto_helper import AESCipher
from tinytuya.core.message_helper import TuyaMessage, pack_message, unpack_message

# TINYTUYA-COUPLING (Layer 3: hand-copied policy). Mirror of
# XenonDevice.NO_PROTOCOL_HEADER_CMDS. If tinytuya adds a command that omits the
# 3.x version header, this tuple goes stale silently — re-copy it.
NEGOTIATION_CMDS = (CT.SESS_KEY_NEG_START, CT.SESS_KEY_NEG_RESP, CT.SESS_KEY_NEG_FINISH)
RETCODE = struct.pack(">I", 0)  # device->client 55AA messages prepend a 0 retcode


# --------------------------------------------------------------------------
# crypto utilities (thin wrappers over tinytuya's AESCipher)
# --------------------------------------------------------------------------

def ecb_encrypt(key, data):
    """AES-ECB encrypt with PKCS#7 padding, raw bytes out (no base64)."""
    return AESCipher(key).encrypt(data, use_base64=False)


def ecb_decrypt(key, data):
    """AES-ECB decrypt of raw (un-base64'd) bytes, padding stripped."""
    return AESCipher(key).decrypt(data, use_base64=False, decode_text=False)


def encrypt_31(local_key, data):
    """v3.1 payload encoding: ``b"3.1" + md5hex[8:24] + base64(ECB(data))``."""
    b64 = AESCipher(local_key).encrypt(data)  # base64=True, padded ECB
    pre = b"data=" + b64 + b"||lpv=" + H.PROTOCOL_VERSION_BYTES_31 + b"||" + local_key
    digest = md5(pre).hexdigest()[8:24].encode("latin1")
    return H.PROTOCOL_VERSION_BYTES_31 + digest + b64


def decrypt_31(local_key, data):
    """Reverse :func:`encrypt_31` (strip ``3.1`` header + 16-byte md5, then ECB)."""
    body = data[len(H.PROTOCOL_VERSION_BYTES_31):]  # drop b"3.1"
    body = body[16:]  # drop md5 hexdigest slice
    return AESCipher(local_key).decrypt(body, decode_text=False)  # base64 ECB


def derive_session_key_ecb(real_key, session_nonce):
    """v3.4 session key: ECB-encrypt(session_nonce) with the real key, 16 bytes."""
    return AESCipher(real_key).encrypt(session_nonce, use_base64=False, pad=False)


def derive_session_key_gcm(real_key, session_nonce, iv):
    """v3.5 session key: GCM-encrypt(session_nonce)[12:28], iv = client_nonce[:12]."""
    # TINYTUYA-COUPLING (Layer 2: AESCipher behavioral contract). The [12:28] slice and
    # the iv= kwarg selecting GCM are tinytuya implementation details, not enforced
    # by any signature. If AESCipher's GCM output layout/kwargs change, this returns
    # the wrong key with NO error. Same kwarg dependence applies to all wrappers
    # above (use_base64=/pad=/decode_text=).
    return AESCipher(real_key).encrypt(
        session_nonce, use_base64=False, pad=False, iv=iv
    )[12:28]


# --------------------------------------------------------------------------
# version profiles
# --------------------------------------------------------------------------

# TINYTUYA-COUPLING (Layer 3: hand-mirrored client policy). Every VersionProfile below
# replicates how tinytuya's XenonDevice *expects a device to behave* per version
# (header placement/timing, session handshake, v3.1 scheme). tinytuya exposes no
# API for this, so a client-side change (moved header, new handshake, a v3.6) does
# NOT propagate here automatically — these classes must be edited by hand. Only
# tests/test_with_tinytuya.py catches the resulting drift.
class VersionProfile:
    """Base = the v3.2/v3.3 family: 55AA + CRC framing, ECB(local_key) payloads, no session."""

    version = "3.3"
    prefix = H.PREFIX_55AA_VALUE
    needs_session = False

    def __init__(self, version):
        self.version = str(version)
        self.version_bytes = self.version.encode("latin1")
        self.version_header = self.version_bytes + H.PROTOCOL_3x_HEADER

    # -- framing ----------------------------------------------------------

    def framing_key(self, session):
        """Key handed to pack/unpack for HMAC framing; None means CRC32."""
        return None

    def unpack_request(self, session, frame):
        """Decode one wire frame into a TuyaMessage whose payload is logical bytes."""
        # TINYTUYA-COUPLING (Layer 2): no_retcode=True because client->device requests
        # carry no retcode (we add it only on responses, see pack_response).
        msg = unpack_message(frame, hmac_key=self.framing_key(session), no_retcode=True)
        payload = self._decrypt_payload(session, msg.cmd, msg.payload)
        return msg._replace(payload=payload)

    def default_response_seqno(self, session):
        """The faithful seqno for a *command response* (config.seqno_mode override
        is applied by Session.response_seqno, which calls this for "faithful").

        TINYTUYA-COUPLING (Layer 2): tinytuya's _get_retcode requires the response
        seqno to EQUAL the request seqno for version < 3.5 (only v3.5 uses a global
        incrementing seqno). So 55AA profiles echo the request seqno; V35 overrides
        this to use the device's own counter. Getting this wrong does not break
        dps decoding but silently leaves cmd_retcode unset on v3.1-3.4.
        """
        return session.req_seqno

    def pack_response(self, session, cmd, wire_payload, seqno=None):
        """Frame already-encoded ``wire_payload`` bytes into a device->client packet.

        ``seqno`` defaults to the session's response seqno (which honours
        config.seqno_mode); device-initiated pushes pass an explicit global seqno.
        """
        if seqno is None:
            seqno = session.response_seqno()
        # TINYTUYA-COUPLING (Layer 2: TuyaMessage field order + retcode asymmetry).
        # TuyaMessage is built POSITIONALLY as
        # (seqno, cmd, retcode, payload, crc, crc_good, prefix, iv); last field is
        # True for 6699 (GCM iv flag) / None for 55AA. The 4-byte retcode is prepended
        # by US for 55AA but handled INSIDE pack_message for 6699. If tinytuya
        # reorders TuyaMessage fields or moves the retcode convention, frames
        # serialize wrong silently.
        if self.prefix == H.PREFIX_6699_VALUE:
            msg = TuyaMessage(
                seqno, cmd, 0, wire_payload, 0, True, self.prefix, True
            )
        else:
            # 55AA device->client messages carry a 4-byte retcode the client strips.
            msg = TuyaMessage(
                seqno, cmd, 0, RETCODE + wire_payload, 0, True, self.prefix, None
            )
        # TINYTUYA-COUPLING (Layer 2): hmac_key=None => CRC32 framing, bytes => HMAC framing.
        return pack_message(msg, hmac_key=self.framing_key(session))

    # -- inner payload codec (data plane) --------------------------------

    def _strip_header(self, cmd, payload):
        if cmd not in NEGOTIATION_CMDS and payload.startswith(self.version_bytes):
            return payload[len(self.version_header):]
        return payload

    def _decrypt_payload(self, session, cmd, payload):
        # v3.2/v3.3 prepend the version header *after* ECB encryption, so it is
        # plaintext on the wire and must be stripped before decrypting.
        payload = self._strip_header(cmd, payload)
        return ecb_decrypt(session.key, payload)

    def encrypt_payload(self, session, data):
        # Real devices prefix data-plane responses with the version header; the
        # client strips it via its startswith() branch (and this is what lets the
        # device22 decode path work). v3.2/v3.3 put it before the ciphertext.
        return self.version_header + ecb_encrypt(session.key, data)

    # -- session negotiation (none for this family) ----------------------

    def negotiation_response(self, session, logical):
        raise NotImplementedError("%s does not negotiate a session key" % self.version)

    def derive_session_key(self, session):
        raise NotImplementedError("%s does not negotiate a session key" % self.version)


class V31Profile(VersionProfile):
    """v3.1: 55AA + CRC, plaintext DP_QUERY requests, md5+ECB+base64 payloads."""

    def _decrypt_payload(self, session, cmd, payload):
        if payload.startswith(H.PROTOCOL_VERSION_BYTES_31):
            return decrypt_31(session.key, payload)
        return payload  # plaintext JSON (e.g. DP_QUERY)

    def encrypt_payload(self, session, data):
        return encrypt_31(session.key, data)


class V34Profile(VersionProfile):
    """v3.4: 55AA + HMAC framing, ECB(session_key) payloads, ECB-derived session."""

    needs_session = True

    def framing_key(self, session):
        return session.key  # real key during handshake, session key afterwards

    def _decrypt_payload(self, session, cmd, payload):
        # v3.4 encrypts the version header *with* the payload, so decrypt first.
        payload = ecb_decrypt(session.key, payload)
        return self._strip_header(cmd, payload)

    def encrypt_payload(self, session, data):
        # v3.4 encrypts the header together with the payload.
        return ecb_encrypt(session.key, self.version_header + data)

    def negotiation_response(self, session, logical):
        # The whole (device_nonce + hmac) blob is ECB-encrypted with the real key.
        return ecb_encrypt(session.real_key, logical)

    def derive_session_key(self, session):
        return derive_session_key_ecb(session.real_key, session.session_nonce())


class V35Profile(VersionProfile):
    """v3.5: 6699 + GCM framing (payload encryption is the framing), GCM session."""

    version = "3.5"
    prefix = H.PREFIX_6699_VALUE
    needs_session = True

    def framing_key(self, session):
        return session.key

    def default_response_seqno(self, session):
        # v3.5 devices reply with a global incrementing seqno, not the request's.
        return session.next_global_seqno()

    def _decrypt_payload(self, session, cmd, payload):
        # 6699 framing already GCM-decrypted the inner payload.
        return self._strip_header(cmd, payload)

    def encrypt_payload(self, session, data):
        # Header rides inside the GCM-encrypted payload (the framing encrypts).
        return self.version_header + data

    def negotiation_response(self, session, logical):
        return logical  # GCM happens in framing

    def derive_session_key(self, session):
        return derive_session_key_gcm(
            session.real_key, session.session_nonce(), session.remote_nonce[:12]
        )


_BUILDERS = {
    "3.1": V31Profile,
    "3.2": VersionProfile,
    "3.3": VersionProfile,
    "3.4": V34Profile,
    "3.5": V35Profile,
}

SUPPORTED_VERSIONS = tuple(sorted(_BUILDERS))


def get_profile(version):
    version = str(version)
    try:
        return _BUILDERS[version](version)
    except KeyError:
        raise ValueError(
            "unsupported protocol version %r (supported: %s)"
            % (version, ", ".join(SUPPORTED_VERSIONS))
        )


def session_hmac(key, data):
    """HMAC-SHA256 used throughout the handshake."""
    return hmac.new(key, data, sha256).digest()
