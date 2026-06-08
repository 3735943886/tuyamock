"""Single-file demo: run the mock in-process and drive it with tinytuya.

    python examples/inprocess_demo.py

Shows (1) the in-process MockDevice API and (2) that the device22
reject -> reconnect mechanism works against the mock.
"""

import tinytuya

import tuyamock

KEY = "thisisarealkey00"
DEV_ID = "eb0123456789abcdefghij"


def demo_basic():
    print("--- basic v3.5 status + set in one process ---")
    with tuyamock.MockDevice(local_key=KEY, version="3.5",
                             dps={"1": True, "20": "white"}) as mock:
        d = tinytuya.Device(DEV_ID, "127.0.0.1", KEY, version=3.5, port=mock.port)
        d.set_socketTimeout(5)

        print("status():", d.status()["dps"])
        d.set_value("20", "red")
        print("after set_value(20,red), live mock.dps:", dict(mock.dps))
        print("status() again:", d.status()["dps"])


def demo_device22_reconnect():
    print("\n--- device22 reject -> reconnect (v3.4) ---")
    with tuyamock.MockDevice(local_key=KEY, version="3.4", dev22=True,
                             dps={"1": False, "20": "white"}) as mock:
        d = tinytuya.Device(DEV_ID, "127.0.0.1", KEY, version=3.4, port=mock.port)
        d.set_socketTimeout(5)

        # First status(): the mock rejects DP_QUERY_NEW with "json obj data
        # unvalid"; tinytuya detects device22, RECONNECTS, and retries via
        # CONTROL_NEW - all inside this single call.
        before = mock.server.connections
        status = d.status()
        after = mock.server.connections

        print("dev_type after first status():", d.dev_type)   # device22
        print("status dps:", status["dps"])                    # real data
        print("connections used by one status():", after - before)  # 2 = reject+reconnect
        assert d.dev_type == "device22"
        assert status["dps"]["1"] is False
        assert (after - before) == 2, "expected a reject + a reconnect"

        # Subsequent commands now work normally.
        d.set_value("1", True)
        print("after set_value(1,True), live mock.dps:", dict(mock.dps))
        assert mock.dps["1"] is True
    print("\nOK - device22 reconnect mechanism works against the mock.")


if __name__ == "__main__":
    demo_basic()
    demo_device22_reconnect()
