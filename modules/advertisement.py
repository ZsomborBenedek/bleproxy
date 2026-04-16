"""DBus LE advertisement object registered with BlueZ's LEAdvertisingManager."""
import dbus
import dbus.service

from modules.constants import LE_ADV_IFACE, DBUS_PROP_IFACE


class BLEAdvertisement(dbus.service.Object):
    PATH_BASE = "/org/bleproxy/advertisement"

    def __init__(self, bus, index: int, device_name: str):
        self.path = f"{self.PATH_BASE}{index}"
        self.local_name = device_name
        super().__init__(bus, self.path)

    def get_path(self):
        return dbus.ObjectPath(self.path)

    def get_properties(self):
        return {
            LE_ADV_IFACE: {
                "Type": "peripheral",
                "LocalName": dbus.String(self.local_name),
                "Appearance": dbus.UInt16(962),  # 962 = Mouse
                "Includes": dbus.Array(["tx-power"], signature="s"),
            }
        }

    @dbus.service.method(DBUS_PROP_IFACE, in_signature="ss", out_signature="v")
    def Get(self, iface, name):
        return self.get_properties()[iface][name]

    @dbus.service.method(DBUS_PROP_IFACE, in_signature="s", out_signature="a{sv}")
    def GetAll(self, iface):
        return self.get_properties()[iface]

    @dbus.service.method(LE_ADV_IFACE)
    def Release(self): pass
