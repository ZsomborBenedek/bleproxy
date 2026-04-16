"""BLE device scanner — discovers nearby devices and prints their addresses."""
import asyncio
import logging

from bleak import BleakScanner

log = logging.getLogger(__name__)


async def scan_devices(adapter: str, duration: float = 10.0) -> dict:
    log.info(f"Scanning on {adapter} for {duration}s ... (Ctrl+C to stop early)\n")
    seen: dict[str, tuple[str, object]] = {}

    def on_device(device, adv_data):
        addr = device.address
        name = device.name or adv_data.local_name or "Unknown"
        rssi = adv_data.rssi if adv_data.rssi else "?"
        if addr not in seen or seen[addr][0] == "Unknown":
            seen[addr] = (name, rssi)
            flag = " <- named" if name != "Unknown" else ""
            print(f"  {addr}  RSSI={rssi:>4}  {name}{flag}")

    async with BleakScanner(detection_callback=on_device, bluez={"adapter": adapter}):
        try:
            await asyncio.sleep(duration)
        except asyncio.CancelledError:
            pass

    print(f"\n[+] Scan complete. Found {len(seen)} device(s).")
    if seen:
        named = {a: v for a, v in seen.items() if v[0] != "Unknown"}
        if named:
            print("\n[+] Named devices only:")
            for addr, (name, rssi) in named.items():
                print(f"    {addr}  {name}  (RSSI={rssi})")

    return seen
