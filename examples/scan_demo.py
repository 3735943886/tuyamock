"""Discovery demo: five mocks (one per version) found by a real ``tinytuya scan``.

    python examples/scan_demo.py

Starts five mock devices, one for each protocol version (v3.1-v3.5), each on its
own loopback IP (127.0.0.1 .. 127.0.0.5) with a distinct gateway id, then runs the
*real* tinytuya scanner (``tinytuya.deviceScan``) and prints what it discovered.

Why distinct loopback IPs: the tinytuya scanner keys discovered devices by the
packet's source address, so every device needs its own IP to show up separately.
Each mock therefore binds its discovery socket to its own 127.0.0.x address (see
``probe_reply``/``host`` in tuyamock.server). On a real LAN this is automatic —
five real devices already have five real IPs.

Discovery here is driven by the periodic passive beacon (UDP 6667); the mocks also
answer active REQ_DEVINFO probes (UDP 7000), but a same-host scanner's probes are
broadcast to the real subnet, not loopback, so the beacon is what the scan sees.
"""

import io
import contextlib

import tinytuya

import tuyamock

KEY = "thisisarealkey00"

# (loopback ip, protocol version, gateway/device id) — one mock per version.
FLEET = [
    ("127.0.0.1", "3.1", "ebmockv31000000000001"),
    ("127.0.0.2", "3.2", "ebmockv32000000000002"),
    ("127.0.0.3", "3.3", "ebmockv33000000000003"),
    ("127.0.0.4", "3.4", "ebmockv34000000000004"),
    ("127.0.0.5", "3.5", "ebmockv35000000000005"),
]

SCAN_SECONDS = 12  # mocks beacon every ~8s, so one full cycle must fit the window


def main():
    mocks = []
    print("Starting %d mock devices (one per version):" % len(FLEET))
    try:
        for ip, version, gw_id in FLEET:
            mock = tuyamock.MockDevice(
                local_key=KEY, version=version, gw_id=gw_id,
                dps={"1": True, "20": "white"},
                host=ip, port=0, discovery=True, discovery_addr=ip,
            )
            mock.start()
            mocks.append((ip, version, gw_id, mock))
            print("  v%s  ip=%s  gwId=%s  (tcp %s:%d)"
                  % (version, ip, gw_id, ip, mock.port))

        print("\nRunning real tinytuya.deviceScan() for ~%ds ...\n" % SCAN_SECONDS)
        # poll=False: we only want discovery, not a stats poll (which would need
        # each device's local key). Silence the scanner's own pretty-printing.
        with contextlib.redirect_stdout(io.StringIO()):
            found = tinytuya.deviceScan(verbose=False, maxretry=SCAN_SECONDS, poll=False)

        by_gwid = {d.get("gwId"): d for d in found.values()}
        print("Scanner discovered %d device(s):\n" % len(found))
        print("  %-5s %-12s %-22s %s" % ("ver", "ip", "gwId", "found?"))
        print("  " + "-" * 52)
        missing = 0
        for ip, version, gw_id, _ in mocks:
            dev = by_gwid.get(gw_id)
            if dev is not None:
                print("  %-5s %-12s %-22s YES (scanner saw v%s)"
                      % (version, dev.get("ip", ip), gw_id, dev.get("version")))
            else:
                missing += 1
                print("  %-5s %-12s %-22s no" % (version, ip, gw_id))

        print()
        if missing:
            print("%d device(s) not seen — try a longer SCAN_SECONDS." % missing)
        else:
            print("All %d versions were discovered by the real tinytuya scanner." % len(mocks))
    finally:
        for _, _, _, mock in mocks:
            with contextlib.suppress(Exception):
                mock.stop()


if __name__ == "__main__":
    main()
