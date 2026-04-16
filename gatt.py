"""
DBus GATT object tree: Descriptor, Characteristic, Service, and Application.

BLEApplication is the ObjectManager root that BlueZ queries via GetManagedObjects
to discover the full service hierarchy.

Writes from the victim are forwarded to the real device via the shared bleak_client
in state.py. Notifications from the real device are pushed via BLECharacteristic.notify().
"""
import asyncio
import logging

import dbus
import dbus.service

import state
from constants import (
    GATT_CHAR_IFACE, GATT_SERVICE_IFACE, DBUS_PROP_IFACE, DBUS_OM_IFACE,
)
from logger import log_event

log = logging.getLogger(__name__)


class BLEDescriptor(dbus.service.Object):
    IFACE = "org.bluez.GattDescriptor1"

    def __init__(self, bus, index: int, uuid: str, flags: list[str], char_path: str):
        self.path = f"{char_path}/desc{index}"
        self.uuid = uuid
        self.flags = flags
        self.value = dbus.Array([], signature="y")
        super().__init__(bus, self.path)

    def get_path(self):
        return dbus.ObjectPath(self.path)

    def get_properties(self):
        return {
            self.IFACE: {
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

    @dbus.service.method(IFACE, in_signature="a{sv}", out_signature="ay")
    def ReadValue(self, options):
        log.debug(f"[GATT-READ] desc path={self.path} uuid={self.uuid} options={dict(options)}")
        return self.value

    @dbus.service.method(IFACE, in_signature="aya{sv}")
    def WriteValue(self, value, options):
        log.debug(f"[GATT-WRIT] desc path={self.path} uuid={self.uuid} options={dict(options)}")
        self.value = dbus.Array(value, signature="y")


class BLECharacteristic(dbus.service.Object):
    def __init__(self, bus, index: int, uuid: str, flags: list[str], service_path: str, handle: int = 0):
        self.path = f"{service_path}/char{index}"
        self.uuid = uuid
        self.flags = flags
        self.handle = handle
        self.value = dbus.Array([], signature="y")
        self.notifying = False
        self.descriptors: list[BLEDescriptor] = []
        super().__init__(bus, self.path)

    def add_descriptor(self, desc: BLEDescriptor):
        self.descriptors.append(desc)

    def get_path(self):
        return dbus.ObjectPath(self.path)

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

    @dbus.service.method(DBUS_PROP_IFACE, in_signature="s", out_signature="a{sv}")
    def GetAll(self, iface):
        log.info(f"[GATT] GetAll char uuid={self.uuid} flags={self.flags}")
        return self.get_properties()[iface]

    @dbus.service.method(GATT_CHAR_IFACE, in_signature="a{sv}", out_signature="ay")
    def ReadValue(self, options):
        log.debug(f"[GATT-READ] char path={self.path} handle={self.handle} uuid={self.uuid} options={dict(options)}")
        val = state.char_values.get(self.handle, bytearray())
        log_event("READ", self.uuid, val)
        return dbus.Array(val, signature="y")

    @dbus.service.method(GATT_CHAR_IFACE, in_signature="aya{sv}")
    def WriteValue(self, value, options):
        log.debug(f"[GATT-WRIT] char path={self.path} handle={self.handle} uuid={self.uuid} options={dict(options)}")
        data = bytearray(value)
        log_event("WRIT", self.uuid, data)

        # Determine write mode: prefer what BlueZ tells us via options["type"],
        # fall back to the preference captured during enumeration
        opt_type = str(options.get("type", "")) if options else ""
        if opt_type == "request":
            response = True
            mode_from_victim = "request"
        elif opt_type == "command":
            response = False
            mode_from_victim = "command"
        else:
            response = state.char_write_prefers_response.get(self.handle, False)
            mode_from_victim = "unknown"

        log.info(
            f"[WRIT-DBG] handle={self.handle} uuid={self.uuid} "
            f"victim_mode={mode_from_victim} forward_response={response} options={dict(options)}"
        )

        if state.bleak_client and state.bleak_client.is_connected and state.asyncio_loop:
            log_event("FWRD", self.uuid, data)
            # Use handle to disambiguate when multiple chars share a UUID (e.g. HID Report)
            target = self.handle if self.handle else self.uuid
            future = asyncio.run_coroutine_threadsafe(
                state.bleak_client.write_gatt_char(target, data, response=response),
                state.asyncio_loop,
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
                f"client_connected={bool(state.bleak_client and state.bleak_client.is_connected)} "
                f"loop_ready={bool(state.asyncio_loop)}"
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
        """Push a notification to the connected victim client."""
        self.value = dbus.Array(data, signature="y")
        self.PropertiesChanged(GATT_CHAR_IFACE, {"Value": self.value}, [])


class BLEService(dbus.service.Object):
    PATH_BASE = "/org/bleproxy/service"

    def __init__(self, bus, index: int, uuid: str, primary: bool = True):
        self.path = f"{self.PATH_BASE}{index}"
        self.uuid = uuid
        self.primary = primary
        self.characteristics: list[BLECharacteristic] = []
        super().__init__(bus, self.path)

    def get_path(self):
        return dbus.ObjectPath(self.path)

    def add_characteristic(self, char: BLECharacteristic):
        self.characteristics.append(char)

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


class BLEApplication(dbus.service.Object):
    """
    ObjectManager root at /org/bleproxy.

    BlueZ calls GetManagedObjects on this path to discover all services,
    characteristics, and descriptors registered by the proxy app.
    """

    def __init__(self, bus):
        self.path = "/org/bleproxy"
        self.services: list[BLEService] = []
        super().__init__(bus, self.path)

    def add_service(self, svc: BLEService):
        self.services.append(svc)

    @dbus.service.method(DBUS_OM_IFACE, out_signature="a{oa{sa{sv}}}")
    def GetManagedObjects(self):
        response = {}
        for svc in self.services:
            response[svc.get_path()] = svc.get_properties()
            for char in svc.characteristics:
                response[char.get_path()] = char.get_properties()
                for desc in char.descriptors:
                    response[desc.get_path()] = desc.get_properties()
        log.info(
            f"[GATT] GetManagedObjects called — returning {len(self.services)} service(s): "
            f"{[str(k) for k in response.keys()]}"
        )
        return response
