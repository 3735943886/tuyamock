"""tuyamock - a protocol-faithful mock of a Tuya local-protocol device.

The device side is implemented entirely with tinytuya's own message/crypto
primitives (``pack_message`` / ``unpack_message`` / ``AESCipher``) so the mock
can serve as an independent ground-truth oracle for *other* Tuya clients
(in any language) without re-implementing the protocol.
"""

from .device import DeviceConfig, TuyaMockDevice, Session
from .server import TuyaMockServer, MockDevice

__all__ = [
    "MockDevice",
    "DeviceConfig",
    "TuyaMockDevice",
    "Session",
    "TuyaMockServer",
]
__version__ = "0.0.5"
