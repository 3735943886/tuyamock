# tuyamock

[![CI](https://github.com/3735943886/tuyamock/actions/workflows/ci.yml/badge.svg)](https://github.com/3735943886/tuyamock/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/tuyamock.svg)](https://pypi.org/project/tuyamock/)
[![Python versions](https://img.shields.io/pypi/pyversions/tuyamock.svg)](https://pypi.org/project/tuyamock/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A protocol-faithful **mock of a Tuya local-protocol device**, built on
[tinytuya](https://github.com/jasonacox/tinytuya)'s own message/crypto
primitives.

It plays the *device* side of the Tuya LAN protocol so you can test Tuya
*clients* end-to-end without real hardware. Because the device side is
implemented with tinytuya's `pack_message` / `unpack_message` / `AESCipher`, the
mock is an **independent oracle**: a client that re-implements the protocol (in
any language) can be validated against it without the validation being circular.

## Why "independent oracle"

The intended workflow is a two-step bootstrap:

1. **mock ⟷ tinytuya client** — prove the mock is protocol-correct using
   tinytuya as the reference client. Once these tests pass, the mock is treated
   as ground truth. *(This is exactly what `tests/test_with_tinytuya.py` does.)*
2. **mock ⟷ client-under-test** — point the other client at the validated mock.
   Any failure is then isolated to that client, not the harness.

## Dependence on tinytuya (read this before upgrading tinytuya)

The mock does **not** re-implement the Tuya protocol — it **imports tinytuya at
runtime and calls tinytuya's own functions** for all crypto/framing. This is
deliberate (it's what makes the mock an independent oracle: the device and the
tinytuya reference client run the *same* byte-level code, so they cannot silently
disagree). But it means the mock's correctness is **coupled to the installed
tinytuya** at three different layers, only one of which auto-adapts. The failure
modes are different per layer — know which is which before bumping the dependency.

### Layer 1 — imported symbols (the linkage surface)

Pulled straight from tinytuya and *called*, never copied. All from **internal**
modules (`tinytuya.core.*`), not a documented/stable public API:

| imported symbol | import path | used in | role |
|-----------------|-------------|---------|------|
| `pack_message` | `tinytuya.core.message_helper` | `protocol.py` (`VersionProfile.pack_response`), `server.py` (discovery beacon) | assemble 55AA / 6699 frames |
| `unpack_message` | `tinytuya.core.message_helper` | `protocol.py` (`VersionProfile.unpack_request`) | disassemble one frame → `TuyaMessage` |
| `TuyaMessage` | `tinytuya.core.message_helper` | `protocol.py` (`pack_response`), `server.py` (`_device_info_packet`) | 8-field namedtuple passed to `pack_message` |
| `parse_header` | `tinytuya.core.message_helper` | `device.py` (`take_frames`) | read `total_length` for stream framing |
| `AESCipher` | `tinytuya.core.crypto_helper` | `protocol.py` (the crypto-utility wrappers) | AES-ECB / AES-GCM + PKCS#7 padding |
| `command_types` (`CT`) | `tinytuya.core` | protocol/device/server | command opcode *values* |
| `header` (`H`) | `tinytuya.core` | protocol/server | prefix/header/version-byte constants |
| `DecodeError` | `tinytuya.core.exceptions` | device/server | raised on short/garbled frames |
| `tinytuya.udpkey` | `tinytuya` (top level) | `server.py` (`_device_info_packet`) | HMAC key for the UDP discovery beacon |

Constants we read out of `H`: `PREFIX_55AA_VALUE`, `PREFIX_6699_VALUE`,
`PROTOCOL_3x_HEADER`, `PROTOCOL_VERSION_BYTES_31`. Opcodes we read out of `CT`:
`SESS_KEY_NEG_START/RESP/FINISH`, `DP_QUERY`, `DP_QUERY_NEW`, `CONTROL`,
`CONTROL_NEW`, `UPDATEDPS`, `HEART_BEAT`, `UDP_NEW`. If tinytuya renames/moves any
of these, the mock fails to **import** — loud, immediate, trivial to diagnose.

### Layer 2 — behavioral contracts (the dangerous, implicit surface)

Beyond mere symbol existence, the mock hard-codes assumptions about *how these
functions behave and what their arguments mean*. These are not enforced by any
type and will not raise on a signature change — they produce **wrong bytes**.
Enumerated so a reviewer knows exactly what to re-verify against tinytuya source:

* **`TuyaMessage` field order/semantics.** We construct it positionally as
  `TuyaMessage(seqno, cmd, retcode, payload, crc, crc_good, prefix, iv)` in
  `protocol.py` `pack_response` (and `server.py` `_device_info_packet`). The last field
  doubles as the GCM-iv/flag: `True` for 6699, `None` for 55AA. If tinytuya
  reorders or repurposes any field, frames serialize wrong with no error.
* **`pack_message(msg, hmac_key=…)`** — we rely on `hmac_key=None` ⇒ CRC32 framing
  and `hmac_key=<bytes>` ⇒ HMAC-SHA256 framing (`VersionProfile.framing_key()`
  returns the session key on v3.4/v3.5, `None` on v3.1–3.3). And that `pack_message`
  reads the prefix from `msg.prefix` to pick 55AA vs 6699.
* **`unpack_message(frame, hmac_key=…, no_retcode=True)`** — we pass
  `no_retcode=True` on requests (client→device frames have no retcode) and instead
  prepend the 4-byte retcode **ourselves** on 55AA responses via the `RETCODE`
  constant (in `pack_response`). The retcode convention living *outside*
  `pack_message` for 55AA but *inside* it for 6699 is a tinytuya-specific asymmetry
  we mirror by hand.
* **`AESCipher` keyword contract.** We depend on the exact kwargs
  `encrypt(data, use_base64=, pad=, iv=)` and
  `decrypt(data, use_base64=, decode_text=)` (see the crypto-utility wrappers at the
  top of `protocol.py`), e.g. `use_base64=False` for raw-bytes ECB on the wire,
  `pad=False` for session-key derivation, and `iv=` selecting GCM mode and being
  prepended to the ciphertext. The v3.5 session key is specifically
  `GCM(nonce, iv=client_nonce[:12])[12:28]` (`derive_session_key_gcm`) — a 16-byte
  slice out of the GCM output whose offset is a tinytuya implementation detail.
* **`parse_header(...).total_length`** is how `take_frames` (in `device.py`)
  re-frames the TCP byte stream (multiple frames per read / frame split across
  reads). A change to that attribute name or its length accounting silently
  corrupts framing.
* **`NO_PROTOCOL_HEADER_CMDS`** — `protocol.NEGOTIATION_CMDS` is a hand-copied
  mirror of `XenonDevice.NO_PROTOCOL_HEADER_CMDS`. If tinytuya adds a command that
  skips the version header, our copy goes stale.

### Layer 3 — client protocol *policy* (hand-mirrored, never auto-adapts)

tinytuya exposes primitives but **not** "how a device is supposed to respond." All
of that is replicated by hand from `XenonDevice` into our `VersionProfile`s (in
`protocol.py`) and command dispatch (`Session` in `device.py`). If tinytuya changes
*client* behaviour (new handshake, moved header, a v3.6), the mock **will not
notice**:

* **version-header placement** — `version_bytes + PROTOCOL_3x_HEADER` is prepended
  *after* ECB on v3.2/3.3 (plaintext on the wire, stripped before decrypt — base
  `VersionProfile._decrypt_payload`/`encrypt_payload`), encrypted *with* the payload
  on v3.4 (`V34Profile`), and carried *inside* the GCM payload on v3.5 (`V35Profile`).
  Real-device data-plane responses must include it or the client's `device22`
  `len & 0x0F` strip heuristic chops the JSON.
* **device22 dialect** — reject the standard query with `json obj data unvalid` (the
  `DATA_UNVALID` constant, used in `Session.handle`) so the client detects device22
  and retries via `CONTROL_NEW`; v3.2 is *always* device22; device22 returns only the
  requested dps. Only valid on v3.2–3.4 (rejected at config in `DeviceConfig` for
  3.1/3.5).
* **standard query opcode by version** — `DP_QUERY` (v3.1–3.3) vs `DP_QUERY_NEW`
  (v3.4+); `--dev22` must reject *whichever* applies (keying only on `DP_QUERY`
  silently no-op'd device22 on v3.4). See the `DP_QUERY`/`DP_QUERY_NEW` branch in
  `Session.handle`.
* **session-key handshake** — START→RESP(nonce+HMAC)→FINISH(verify HMAC, install
  key), key swapped only *after* FINISH; v3.4 key = `ECB(session_nonce)`, v3.5 key =
  the GCM slice above (`Session._handle_neg_start`/`_handle_neg_finish` plus each
  profile's `derive_session_key`).
* **v3.1 payload scheme** — `b"3.1" + md5hex[8:24] + base64(ECB(data))`
  (`encrypt_31`/`decrypt_31` in `protocol.py`).
* **device→client seqno** is a device-side incrementing counter, not a request echo
  (`Session.__init__` / `pack_response`).

### Summary: does the mock auto-adapt to a tinytuya algorithm change?

| change in tinytuya | mock reaction |
|--------------------|---------------|
| internals of `pack_message`/`unpack_message`/`AESCipher`/HMAC/GCM | **auto-adapts** (same code path runs on both ends) |
| value of an opcode or magic constant in `CT`/`H` | **auto-adapts** (we read the symbol, not a literal) |
| rename/move of an imported internal symbol | **breaks loudly** at import (Layer 1) |
| `TuyaMessage` field order, kwarg contract, `total_length` semantics | **breaks silently → wrong bytes** (Layer 2) |
| client *policy*: header timing, device22 flow, handshake, new version | **does not adapt** — must hand-edit `protocol.py`/`device.py` (Layer 3) |

So: low-level crypto/framing is *delegated* and tracks tinytuya for free; the
per-version protocol *policy* is *replicated* and must be maintained by hand. Layer 2
is the trap — it neither auto-adapts nor fails loudly.

> Every Layer-1/2/3 site above is tagged in the source with a `TINYTUYA-COUPLING`
> comment (noting its layer). `grep -rn TINYTUYA-COUPLING src/` enumerates exactly
> what to re-verify against tinytuya on an upgrade.

## Install

```bash
pip install tuyamock          # pulls tinytuya from PyPI
```

For development (run the test suite, editable install):

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[test]"
```

## Usage

```bash
# v3.5 bulb on the default port (6668)
python -m tuyamock --version 3.5 --local-key thisisarealkey00

# OS-assigned port (printed as the first stdout line) for parallel tests
python -m tuyamock --port 0 --version 3.4 --local-key thisisarealkey00

# inject data points; emulate the device22 status quirk (v3.3/v3.4)
python -m tuyamock --version 3.3 --dev22 --dps '{"1": true, "20": "white"}'
```

The first line on **stdout** is always the bound TCP port (handy with
`--port 0`); all logging goes to **stderr** (`-v` = info, `-vv` = debug).

### Key options

| flag | meaning |
|------|---------|
| `--version {3.1,3.2,3.3,3.4,3.5}` | protocol version to emulate |
| `--local-key` | 16-byte device key |
| `--port` | TCP port (`0` = OS-assigned, printed to stdout) |
| `--dps` | canned data points as a JSON object |
| `--dev22` | emulate device22 (only valid on v3.2–v3.4; see below) |
| `--discovery` | be discoverable by `tinytuya scan` — passive beacon + active probe reply (see below) |
| `--no-probe-reply` | with `--discovery`, passive beacon only (don't bind UDP 7000) |
| `--max-connections N` | exit cleanly after N client connections (test isolation) |

## In-process (Python API)

For tests you can run the mock in a background thread and drive it with tinytuya
from a single file — no subprocess, no port wrangling:

```python
import tinytuya
import tuyamock

with tuyamock.MockDevice(local_key="thisisarealkey00", version="3.5",
                         dps={"1": True, "20": "white"}) as mock:
    d = tinytuya.Device("eb0123456789abcdefghij", "127.0.0.1",
                        "thisisarealkey00", version=3.5, port=mock.port)
    print(d.status()["dps"])     # {'1': True, '20': 'white'}
    d.set_value("20", "red")
    print(mock.dps)              # {'1': True, '20': 'red'}  (live device state)
```

`MockDevice(...)` takes the same options as the CLI (`version`, `dps`, `dev22`,
`port=0` for an OS-assigned port, …). `mock.port` is the bound port, `mock.dps`
is the live device state, and `mock.server.connections` counts accepted
connections. See [`examples/inprocess_demo.py`](examples/inprocess_demo.py).

The device22 reject→reconnect handshake works against the mock: a single
`status()` on a device22 device uses two connections (the mock rejects the
standard query, tinytuya detects device22, reconnects, and retries via
`CONTROL_NEW`).

## Connection lifecycle (heartbeat, idle timeout, monitor)

The mock models how a real Tuya device manages its single local TCP connection:

- **Idle timeout** — a real device drops the connection if it receives no packet
  for ~30s, which is why clients send heartbeats. `MockDevice(idle_timeout=30.0)`
  (default 30s; `0`/`None` disables). A heartbeat resets the timer.
- **Heartbeats** — `HEART_BEAT` is answered with an empty-payload ack.
- **nowait / send-only clients** — a client that fires `nowait` commands or raw
  `send()`s without reading the reply will not crash or wedge the mock (the reply
  is attempted and the dropped socket is cleaned up on the next loop).
- **Device-initiated push (monitor)** — `mock.push(dps)` sends an asynchronous
  `STATUS` update to the connected client, which a monitoring loop picks up via
  `receive()`. tinytuya's `examples/monitor.py` pattern works against the mock;
  see [`examples/monitor_demo.py`](examples/monitor_demo.py).

```python
with tuyamock.MockDevice(local_key="thisisarealkey00", version="3.5",
                         dps={"20": "white"}) as mock:
    # ... a monitoring tinytuya client is connected ...
    mock.dps["20"] = "red"
    mock.push({"20": "red"})       # client receives this via receive()
```

Response seqno is handled per the protocol: v3.1–3.4 echo the request seqno
(so tinytuya pairs the reply's retcode), v3.5 uses a global incrementing seqno.

### Misbehaving on purpose (`seqno_mode`)

Real devices are inconsistent about seqno, so a robust client must not depend on
it for correctness. `MockDevice(seqno_mode=...)` lets you deliberately misbehave
to stress-test that:

| mode | behaviour |
|------|-----------|
| `"faithful"` (default) | echo for v3.1–3.4, global for v3.5 (what real devices/tinytuya expect) |
| `"global"` | always a global incrementing seqno |
| `"echo"` | always echo the request seqno |
| `"zero"` | always 0 |
| `callable(session) -> int` | any custom scheme |

The data plane is independent of seqno, so a correct client still decodes dps
under any mode; only tinytuya's `cmd_retcode` pairing is affected. Also on the
CLI: `--seqno-mode`, `--idle-timeout`.

## Stateful device

The mock keeps live dps state and responds to the full tinytuya client command
surface, so a `set` is reflected by a later `status()`:

| tinytuya client call | wire command | mock behaviour |
|----------------------|--------------|----------------|
| `status()` | `DP_QUERY` / `DP_QUERY_NEW` | returns current dps |
| `set_value()` / `set_status()` / `turn_on()` / `turn_off()` | `CONTROL` (`CONTROL_NEW` on v3.4+) | merges dps into state, reports the changed dps |
| `set_multiple_values()` | `CONTROL` | merges all, reports changed |
| `updatedps()` | `UPDATEDPS` | reports the requested dpIds |
| `heartbeat()` | `HEART_BEAT` | empty-payload ack |

State is shared across connections (tinytuya opens a fresh connection per
command by default), so set-then-query works end-to-end.

```python
import tinytuya
d = tinytuya.Device("eb0123456789abcdefghij", "127.0.0.1",
                    "thisisarealkey00", version=3.5, port=PORT)
d.set_value("1", True)          # -> {"dps": {"1": True}}
d.status()["dps"]["1"]          # -> True   (persisted)
```

## Discovery (`tinytuya scan`)

With `--discovery` (CLI) or `MockDevice(discovery=True)` the mock is found by a real
`tinytuya scan` / `tinytuya.deviceScan()` for **every version (v3.1–v3.5)**, via the
two mechanisms a real device uses — both framed exactly like a real device announce
(6699 + `tinytuya.udpkey`), so the scanner's own `decrypt_udp` decodes them:

* **Passive beacon** — every ~8 s the mock broadcasts its device-info JSON to UDP
  `6667`, which the scanner picks up by listening. The device's protocol version
  rides in the JSON's `version` field, so one packet shape serves all five.
* **Active probe reply** — the scanner also broadcasts a `REQ_DEVINFO` (0x25) probe
  to UDP `7000`; the mock binds `7000` and answers with its device-info. On by
  default; pass `--no-probe-reply` (or `probe_reply=False`) to skip the `7000` bind.

```bash
python -m tuyamock --version 3.5 --local-key thisisarealkey00 --discovery &
tinytuya scan          # lists the mock as a v3.5 device at 127.0.0.1
```

[`examples/scan_demo.py`](examples/scan_demo.py) starts one mock per version on its
own loopback IP and shows a real `tinytuya.deviceScan()` discovering all five.

The mock binds `7000` with `SO_REUSEPORT` — the same option the tinytuya scanner
sets on its own `7000` listener — so a scanner and the mock **coexist on one host**.
(One caveat of same-host use: a unicast probe reply to `7000` may be load-balanced
to either listener, but the passive beacon makes discovery reliable regardless. On a
real LAN, device and app are on separate hosts, so there is no overlap at all.)

## Supported protocol versions

| version | framing | payload crypto | session key |
|---------|---------|----------------|-------------|
| 3.1 | 55AA + CRC32 | `3.1`+md5+base64(AES-ECB) | — |
| 3.2 | 55AA + CRC32 | AES-ECB(local_key) | — *(client uses device22 dialect)* |
| 3.3 | 55AA + CRC32 | AES-ECB(local_key) | — |
| 3.4 | 55AA + HMAC-SHA256 | AES-ECB(session_key) | ECB-derived |
| 3.5 | 6699 + AES-GCM | (GCM is the framing) | GCM-derived |

### device22

A `device22` device returns only the data points it is explicitly asked for and
rejects the standard status query with `json obj data unvalid`, forcing the
client to retry via `CONTROL_NEW`. Enable it with `--dev22`.

It is only meaningful where the tinytuya reference client supports it:

| version | device22 |
|---------|----------|
| 3.1 | not supported — `--dev22` is **rejected at startup** |
| 3.2 | **always** device22 (the v3.2 client forces the dialect; `--dev22` optional) |
| 3.3 | opt-in via `--dev22` (client auto-detects from the rejected query) |
| 3.4 | opt-in via `--dev22` (rejects `DP_QUERY_NEW`, not `DP_QUERY`) |
| 3.5 | not supported — `--dev22` is **rejected at startup** |

The standard status query differs by version (`DP_QUERY` on v3.1–3.3,
`DP_QUERY_NEW` on v3.4+), and `--dev22` rejects whichever one applies.

## Architecture

* **`protocol.py`** — per-version `VersionProfile`s plus shared crypto/framing
  utilities. Each profile captures framing, the payload codec, and session
  negotiation, so the rest of the code is version-agnostic.
* **`device.py`** — `DeviceConfig` (static config), `Session` (per-connection
  nonces/keys), and command dispatch.
* **`server.py`** — single-client IPv4 TCP loop (avoids the original example's
  `AF_INET6` dual-stack trap), `--port 0` support, clean SIGTERM/SIGINT
  shutdown, optional UDP discovery beacon. Serving **one connection at a time is
  protocol-faithful**, not a limitation: a real Tuya device handles a single local
  TCP connection and does not support concurrent local connections, so clients talk
  to it serially (a fresh connection per command). Adding multi-client support
  would make the mock behave *unlike* real hardware — don't.
* **`cli.py`** — the `python -m tuyamock` entry point.
