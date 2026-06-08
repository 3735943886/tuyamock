"""Command-line entry point: ``python -m tuyamock`` / ``tuyamock``."""

import argparse
import json
import logging
import signal
import sys

from .device import DeviceConfig, DEFAULT_DPS, SUPPORTED_VERSIONS
from .server import TuyaMockServer


def _parse_dps(raw):
    if raw is None:
        return dict(DEFAULT_DPS)
    try:
        dps = json.loads(raw)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("--dps must be valid JSON: %s" % exc)
    if not isinstance(dps, dict):
        raise argparse.ArgumentTypeError("--dps must be a JSON object")
    return {str(k): v for k, v in dps.items()}


def build_parser():
    p = argparse.ArgumentParser(
        prog="tuyamock",
        description="Mock a Tuya local-protocol device for testing clients.",
    )
    p.add_argument(
        "--version", default="3.5", choices=list(SUPPORTED_VERSIONS),
        help="Tuya protocol version to emulate (default: 3.5).",
    )
    p.add_argument(
        "--local-key", default="thisisarealkey00",
        help="16-byte device local key (default: thisisarealkey00).",
    )
    p.add_argument(
        "--host", default="127.0.0.1",
        help="Interface to bind (default: 127.0.0.1).",
    )
    p.add_argument(
        "--port", type=int, default=6668,
        help="TCP port to bind; 0 lets the OS pick a free port (default: 6668).",
    )
    p.add_argument(
        "--dps", type=_parse_dps, default=None, dest="dps",
        help="Canned data points as a JSON object (default: a sample RGBCW bulb).",
    )
    p.add_argument(
        "--gw-id", default="eb0123456789abcdefghij",
        help="Gateway/device id advertised in discovery.",
    )
    p.add_argument(
        "--product-key", default="keydeadbeef12345",
        help="Product key advertised in discovery.",
    )
    p.add_argument(
        "--dev22", action="store_true",
        help="Emulate a 'device22' quirk: reject DP_QUERY so the client falls "
             "back to the CONTROL_NEW status path (v3.3/v3.4).",
    )
    p.add_argument(
        "--discovery", action="store_true",
        help="Periodically emit the UDP discovery beacon (off by default).",
    )
    p.add_argument(
        "--discovery-addr", default="127.0.0.1",
        help="Address used in/for the discovery beacon (default: 127.0.0.1).",
    )
    p.add_argument(
        "--max-connections", type=int, default=None,
        help="Exit after serving this many client connections (default: run forever).",
    )
    p.add_argument(
        "-v", "--verbose", action="count", default=0,
        help="Increase log verbosity (-v info, -vv debug). Logs go to stderr.",
    )
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)

    level = logging.WARNING
    if args.verbose == 1:
        level = logging.INFO
    elif args.verbose >= 2:
        level = logging.DEBUG
    logging.basicConfig(level=level, stream=sys.stderr,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    try:
        config = DeviceConfig(
            local_key=args.local_key,
            dps=args.dps,
            version=args.version,
            gw_id=args.gw_id,
            product_key=args.product_key,
            dev22=args.dev22,
        )
    except ValueError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2

    server = TuyaMockServer(
        config,
        host=args.host,
        port=args.port,
        discovery=args.discovery,
        discovery_addr=args.discovery_addr,
    )

    # Translate SIGTERM into KeyboardInterrupt so serve_forever() unwinds the
    # same clean-shutdown path used for Ctrl-C.
    def _term(_signum, _frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, _term)

    try:
        port = server.start()
    except OSError as exc:
        print("error: could not bind %s:%d: %s" % (args.host, args.port, exc),
              file=sys.stderr)
        return 1

    # First stdout line is the bound port, flushed immediately, so a parent
    # process spawning the mock on port 0 can learn where to connect.
    print(port, flush=True)

    server.serve_forever(max_connections=args.max_connections)
    return 0


if __name__ == "__main__":
    sys.exit(main())
