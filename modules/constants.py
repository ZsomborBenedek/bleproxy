"""BlueZ and DBus interface names used throughout the proxy."""

BLUEZ_SERVICE       = "org.bluez"
LE_ADV_MANAGER      = "org.bluez.LEAdvertisingManager1"
LE_ADV_IFACE        = "org.bluez.LEAdvertisement1"
GATT_MANAGER_IFACE  = "org.bluez.GattManager1"
GATT_SERVICE_IFACE  = "org.bluez.GattService1"
GATT_CHAR_IFACE     = "org.bluez.GattCharacteristic1"
DBUS_PROP_IFACE     = "org.freedesktop.DBus.Properties"
AGENT_IFACE         = "org.bluez.Agent1"
AGENT_MANAGER_IFACE = "org.bluez.AgentManager1"
AGENT_PATH          = "/org/bleproxy/agent"
DBUS_OM_IFACE       = "org.freedesktop.DBus.ObjectManager"

# BlueZ 5.72+ owns these services internally; registering them via an app fails
BLUEZ_RESERVED_SERVICES = {
    "00001800-0000-1000-8000-00805f9b34fb",  # Generic Access
    "00001801-0000-1000-8000-00805f9b34fb",  # Generic Attribute
}

# BlueZ handles CCCD/SCCD automatically — don't expose them in the proxy app
# or BlueZ silently breaks ATT service discovery
BLUEZ_MANAGED_DESCRIPTORS = {
    "00002902-0000-1000-8000-00805f9b34fb",  # CCCD
    "00002903-0000-1000-8000-00805f9b34fb",  # SCCD
}

# Security flags stripped from mirrored characteristics so un-paired clients can connect
SECURITY_FLAGS = {
    "encrypt-read", "encrypt-write",
    "encrypt-authenticated-read", "encrypt-authenticated-write",
    "secure-read", "secure-write",
    "authorize",
}
