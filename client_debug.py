#!/usr/bin/env python3
"""
BLE client-side debug tool for validating a peripheral (real or fake).

Examples:
  python3 client_debug.py --address 5C:F3:70:79:44:77 --scan-seconds 8
    python3 client_debug.py --name "MX Anywhere 2S - Fake" --scan-seconds 8
  python3 client_debug.py --address 5C:F3:70:79:44:77 --adapter hci0 --read-all
  python3 client_debug.py --address 5C:F3:70:79:44:77 --listen-seconds 30
  python3 client_debug.py --address 5C:F3:70:79:44:77 --write-handle 0x40 --write-hex 010203
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
import traceback
from datetime import datetime
from typing import Any

from bleak import BleakClient, BleakScanner


def setup_verbose_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="[%(asctime)s] %(levelname)s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    logging.getLogger("bleak").setLevel(logging.DEBUG)
    logging.getLogger("asyncio").setLevel(logging.DEBUG)


def ts() -> str:
    return datetime.now().strftime("%H:%M:%S.%f")[:-3]


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Client-side BLE debug helper")
    p.add_argument("--address", default=None, help="Target peripheral MAC address (optional when --name is used)")
    p.add_argument("--name", default=None, help="Peripheral local name to match (supports name-only mode)")
    p.add_argument(
        "--name-match",
        choices=["exact", "contains"],
        default="exact",
        help="How to match --name during discovery (default: exact)",
    )
    p.add_argument("--adapter", default=None, help="BlueZ adapter, example: hci0")
    p.add_argument("--scan-seconds", type=float, default=8.0, help="Scan timeout before connect")
    p.add_argument("--dump-scan", action="store_true", help="Print all devices seen during scan window")

    p.add_argument("--read-all", action="store_true", help="Try reading every readable characteristic")
    p.add_argument("--no-subscribe", action="store_true", help="Do not subscribe to notify/indicate characteristics")
    p.add_argument("--listen-seconds", type=float, default=20.0, help="How long to listen for notifications")

    p.add_argument("--write-handle", type=lambda v: int(v, 0), default=None, help="Characteristic handle to write (decimal or hex)")
    p.add_argument("--write-hex", default=None, help="Hex payload to write, example: 010203")
    p.add_argument(
        "--write-response",
        choices=["auto", "request", "command"],
        default="auto",
        help="Write mode: auto chooses by characteristic properties",
    )
    return p.parse_args()


async def find_device(
    address: str | None,
    name: str | None,
    timeout: float,
    adapter: str | None,
    dump_scan: bool,
    name_match: str,
):
    scanner_kwargs: dict[str, Any] = {}
    if adapter:
        scanner_kwargs["bluez"] = {"adapter": adapter}

    def _name_match(device, adv_data):
        if not name:
            return False
        wanted = name.strip().lower()
        local_name = (adv_data.local_name or "").strip().lower()
        device_name = (device.name or "").strip().lower()
        if name_match == "contains":
            return wanted in local_name or wanted in device_name
        return wanted == local_name or wanted == device_name

    if dump_scan:
        print(f"[{ts()}] SCAN-DUMP begin adapter={adapter or 'default'} timeout={timeout}s")
        discovered = await BleakScanner.discover(timeout=timeout, return_adv=True, **scanner_kwargs)
        if not discovered:
            print(f"[{ts()}] SCAN-DUMP no devices discovered")
        else:
            for addr, (device, adv_data) in sorted(discovered.items(), key=lambda item: str(item[0])):
                dev_name = device.name or adv_data.local_name or "Unknown"
                rssi = adv_data.rssi if adv_data.rssi is not None else "?"
                print(f"[{ts()}] SCAN-DEV address={addr} rssi={rssi} name={dev_name}")

    if address:
        print(f"[{ts()}] SCAN address={address} adapter={adapter or 'default'} timeout={timeout}s")
        dev = await BleakScanner.find_device_by_address(address, timeout=timeout, **scanner_kwargs)
    else:
        print(f"[{ts()}] SCAN name={name!r} adapter={adapter or 'default'} timeout={timeout}s")
        dev = await BleakScanner.find_device_by_filter(_name_match, timeout=timeout, **scanner_kwargs)

    if not dev and sys.platform == "darwin":
        print(f"[{ts()}] WARN address lookup failed on macOS (CoreBluetooth).")
        if name:
            print(f"[{ts()}] SCAN-FALLBACK name={name!r} timeout={timeout}s")

            dev = await BleakScanner.find_device_by_filter(_name_match, timeout=timeout, **scanner_kwargs)
            if not dev:
                print(f"[{ts()}] WARN fallback name lookup did not find {name!r}")
        else:
            print(f"[{ts()}] INFO on macOS, pass --name for fallback discovery when using --address")

    if dev and name and (dev.name or "") != name:
        print(f"[{ts()}] WARN found device name mismatch: got={dev.name!r} expected={name!r}")

    return dev


def dump_services(client: BleakClient):
    print(f"[{ts()}] GATT services={len(client.services)}")
    by_handle = {}
    for svc in client.services:
        print(f"  [SVC] {svc.uuid}")
        for ch in svc.characteristics:
            props = ",".join(ch.properties)
            print(f"    [CHR] handle={ch.handle:<4} uuid={ch.uuid} props=[{props}]")
            by_handle[ch.handle] = ch
            for d in ch.descriptors:
                print(f"      [DSC] handle={d.handle:<4} uuid={d.uuid}")
    return by_handle


async def try_read_all(client: BleakClient, by_handle):
    for handle, ch in by_handle.items():
        if "read" not in ch.properties:
            continue
        try:
            data = await client.read_gatt_char(handle)
            print(f"[{ts()}] READ handle={handle} uuid={ch.uuid} data={bytes(data).hex()}")
        except Exception as e:
            print(f"[{ts()}] READ-ERR handle={handle} uuid={ch.uuid} error={e}")


async def try_write(client: BleakClient, by_handle, handle: int, payload_hex: str, mode: str):
    if handle not in by_handle:
        print(f"[{ts()}] WRITE-ERR handle={handle} not found in discovered characteristics")
        return

    ch = by_handle[handle]
    payload = bytes.fromhex(payload_hex)

    if mode == "request":
        response = True
    elif mode == "command":
        response = False
    else:
        can_req = "write" in ch.properties
        can_cmd = "write-without-response" in ch.properties
        response = can_req and not can_cmd

    print(
        f"[{ts()}] WRITE handle={handle} uuid={ch.uuid} mode={mode} "
        f"response={response} data={payload.hex()}"
    )
    try:
        await client.write_gatt_char(handle, payload, response=response)
        print(f"[{ts()}] WRITE-OK handle={handle} uuid={ch.uuid}")
    except Exception as e:
        print(f"[{ts()}] WRITE-ERR handle={handle} uuid={ch.uuid} error={e}")


async def subscribe_and_listen(client: BleakClient, by_handle, seconds: float):
    subs = []

    def mk_handler(handle: int, uuid: str):
        def _handler(_char, data: bytearray):
            print(f"[{ts()}] NOTF handle={handle} uuid={uuid} data={bytes(data).hex()}")
        return _handler

    for handle, ch in by_handle.items():
        if not ({"notify", "indicate"}.intersection(ch.properties)):
            continue
        try:
            await client.start_notify(handle, mk_handler(handle, ch.uuid))
            subs.append(handle)
            print(f"[{ts()}] SUB-OK handle={handle} uuid={ch.uuid}")
        except Exception as e:
            print(f"[{ts()}] SUB-ERR handle={handle} uuid={ch.uuid} error={e}")

    print(f"[{ts()}] LISTEN seconds={seconds} active_subscriptions={len(subs)}")
    try:
        await asyncio.sleep(seconds)
    finally:
        for handle in subs:
            try:
                await client.stop_notify(handle)
            except Exception:
                pass


async def main_async(args: argparse.Namespace):
    if not args.address and not args.name:
        raise ValueError("Use at least one of --address or --name")

    if (args.write_handle is None) ^ (args.write_hex is None):
        raise ValueError("Use --write-handle and --write-hex together")

    dev = await find_device(
        args.address,
        args.name,
        args.scan_seconds,
        args.adapter,
        args.dump_scan,
        args.name_match,
    )
    if not dev:
        print(f"[{ts()}] ERROR target not found during scan")
        return 2

    if args.name and args.name_match == "exact":
        found_name = (dev.name or "").strip()
        if found_name != args.name.strip():
            print(
                f"[{ts()}] ERROR strict name match failed: "
                f"found_name={dev.name!r} expected={args.name!r}"
            )
            return 2

    client_kwargs: dict[str, Any] = {"timeout": 20.0}
    if args.adapter:
        client_kwargs["bluez"] = {"adapter": args.adapter}

    disconnected = asyncio.Event()

    def on_disconnect(_):
        print(f"[{ts()}] DISCONNECTED")
        disconnected.set()

    print(f"[{ts()}] CONNECT address={dev.address} name={dev.name}")
    async with BleakClient(dev, disconnected_callback=on_disconnect, **client_kwargs) as client:
        print(f"[{ts()}] CONNECTED is_connected={client.is_connected}")
        by_handle = dump_services(client)

        if args.read_all:
            await try_read_all(client, by_handle)

        if args.write_handle is not None and args.write_hex is not None:
            await try_write(client, by_handle, args.write_handle, args.write_hex, args.write_response)

        if not args.no_subscribe:
            await subscribe_and_listen(client, by_handle, args.listen_seconds)

        if disconnected.is_set():
            return 3

    print(f"[{ts()}] DONE")
    return 0


def main():
    setup_verbose_logging()
    args = parse_args()
    print(f"[{ts()}] ARGS {vars(args)}")
    print(f"[{ts()}] PLATFORM {sys.platform}")
    try:
        rc = asyncio.run(main_async(args))
    except KeyboardInterrupt:
        print(f"[{ts()}] INTERRUPTED")
        rc = 130
    except Exception as e:
        print(f"[{ts()}] FATAL type={type(e).__name__} error={e!r}")
        print(traceback.format_exc())
        rc = 1
    raise SystemExit(rc)


if __name__ == "__main__":
    main()
