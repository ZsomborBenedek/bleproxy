#!/usr/bin/env python3
"""
BLE MITM proxy using Bleak (central) + BlueZ DBus (peripheral).

Usage:
    sudo python3 ble_mitm.py --scan                                              # scan only
    sudo python3 ble_mitm.py --scan --adapter hci3                               # scan on specific adapter
    sudo python3 ble_mitm.py --target FF:56:E4:83:18:1E                          # run proxy
    sudo python3 ble_mitm.py --target FF:56:E4:83:18:1E --central hci3 --peripheral hci4
"""
import asyncio
import argparse
import logging

from modules.scanner import scan_devices
from modules.proxy import run_proxy

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
log = logging.getLogger(__name__)


def main():
    parser = argparse.ArgumentParser(description="BLE MITM proxy with scanner")
    parser.add_argument("--scan",        action="store_true", help="Scan for nearby BLE devices")
    parser.add_argument("--duration",    type=float, default=10.0, help="Scan duration in seconds (default: 10)")
    parser.add_argument("--adapter",     default="hci0", help="Adapter for scanning (default: hci0)")
    parser.add_argument("--target",      help="Target device MAC for proxy mode")
    parser.add_argument("--central",     default="hci3", help="Adapter to connect to target (default: hci3)")
    parser.add_argument("--peripheral",  default="hci4", help="Adapter to advertise on (default: hci4)")
    args = parser.parse_args()

    try:
        if args.scan:
            asyncio.run(scan_devices(args.adapter, args.duration))
        elif args.target:
            asyncio.run(run_proxy(args.target, args.central, args.peripheral))
        else:
            parser.print_help()
    except KeyboardInterrupt:
        log.info("Interrupted, exiting.")


if __name__ == "__main__":
    main()
