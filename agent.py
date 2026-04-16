"""Bluetooth pairing agent that accepts all requests without user interaction (Just Works)."""
import dbus
import dbus.service

from constants import AGENT_IFACE, AGENT_PATH


class SimpleAgent(dbus.service.Object):
    """NoInputNoOutput pairing agent — auto-accepts all pairing and authorization requests."""

    def __init__(self, bus):
        super().__init__(bus, AGENT_PATH)

    @dbus.service.method(AGENT_IFACE, in_signature="os", out_signature="")
    def AuthorizeService(self, _device, _uuid): pass

    @dbus.service.method(AGENT_IFACE, in_signature="o", out_signature="")
    def RequestAuthorization(self, _device): pass

    @dbus.service.method(AGENT_IFACE, in_signature="", out_signature="")
    def Cancel(self): pass
