"""Monitor demo: tinytuya's monitor loop driven against an in-process mock.

Mirrors tinytuya/examples/monitor.py (persistent connection, periodic heartbeat,
receive() for async updates) but runs the device side as a tuyamock.MockDevice in
the same process, and uses mock.push() to inject a device-initiated state change
that the monitor loop picks up.

    python examples/monitor_demo.py
"""

import threading
import time

import tinytuya

import tuyamock

KEY = "thisisarealkey00"
DEV_ID = "eb0123456789abcdefghij"


def main():
    with tuyamock.MockDevice(local_key=KEY, version="3.5",
                             dps={"1": True, "20": "white"}) as mock:
        d = tinytuya.OutletDevice(DEV_ID, "127.0.0.1", KEY, version=3.5,
                                  persist=True, port=mock.port)
        d.set_socketTimeout(2)

        # A background "device" that changes a dp and pushes an update after 1.5s,
        # simulating a physical button press / sensor change on the real device.
        def change_state_later():
            time.sleep(1.5)
            mock.dps["20"] = "red"
            mock.push({"20": "red"})
            print("   [device] pushed dp 20 -> red")

        threading.Thread(target=change_state_later, daemon=True).start()

        print(" > Send Request for Status <")
        print("Initial Status:", d.status().get("dps"))

        print(" > Begin Monitor Loop (a few iterations) <")
        KEEPALIVE = 1.0
        heartbeat_time = time.time() + KEEPALIVE
        deadline = time.time() + 4
        while time.time() < deadline:
            if time.time() >= heartbeat_time:
                d.heartbeat(nowait=True)        # keep-alive (resets device idle timer)
                heartbeat_time = time.time() + KEEPALIVE
                data = None
            else:
                data = d.receive()              # listen for an async update
            if isinstance(data, dict) and "dps" in data:
                print("   [monitor] received async update:", data["dps"])

        print("Final device state:", dict(mock.dps))


if __name__ == "__main__":
    main()
