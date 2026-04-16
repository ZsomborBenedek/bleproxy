"""
Monitor victim-side BLE connections on the peripheral adapter via DBus signals.

Logs four lifecycle events:
  VSEE — BlueZ sees a new device (InterfacesAdded)
  VCON — device connected
  VDIS — device disconnected
  VREM — BlueZ removes the device object (InterfacesRemoved)
"""
import logging

import dbus

from constants import BLUEZ_SERVICE, DBUS_PROP_IFACE, DBUS_OM_IFACE
from logger import log_connection

log = logging.getLogger(__name__)


def setup_victim_monitoring(bus, peripheral_adapter: str) -> None:
    """Register DBus signal receivers to track client connections on the peripheral adapter."""
    adapter_path = f"/org/bluez/{peripheral_adapter}"

    def _addr_from_path(path: str) -> str:
        """Extract a colon-formatted MAC address from a BlueZ object path."""
        if "/dev_" not in path:
            return "unknown"
        dev_token = path.split("/dev_", 1)[1].split("/", 1)[0]
        return dev_token.replace("_", ":")

    def on_properties_changed(iface, changed, _invalidated, path=None):
        # Log every PropertiesChanged on device paths so we can see BlueZ activity
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
            event = "VCON" if changed["Connected"] else "VDIS"
            log_connection(event, addr, f"name={name}")

        if "ServicesResolved" in changed:
            log_connection("VSVC", addr, f"ServicesResolved={bool(changed['ServicesResolved'])}")

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
        on_properties_changed,
        dbus_interface=DBUS_PROP_IFACE,
        signal_name="PropertiesChanged",
        path_keyword="path",
    )
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
