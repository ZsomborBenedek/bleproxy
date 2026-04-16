"""
Enumerate GATT services, characteristics, and descriptors from a connected BleakClient.

Two things are normalised during enumeration so the proxy works transparently:
- Security flags are stripped so un-paired clients can connect to the proxy without
  pairing. (The real device already enforces these; the proxy doesn't need to.)
- BlueZ-managed descriptors (CCCD 0x2902, SCCD 0x2903) are excluded because BlueZ
  owns them internally for notify/indicate characteristics — registering them in an
  app causes BlueZ to silently break ATT service discovery.
"""
import logging
from dataclasses import dataclass, field

from constants import SECURITY_FLAGS, BLUEZ_MANAGED_DESCRIPTORS

log = logging.getLogger(__name__)


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


async def enumerate_services(client) -> EnumResult:
    """Collect service/characteristic metadata from an open BleakClient (no reads)."""
    services: list[ServiceInfo] = []
    service_uuids: list[str] = []

    for svc in client.services:
        svc_info = ServiceInfo(uuid=str(svc.uuid))
        service_uuids.append(str(svc.uuid))

        for char in svc.characteristics:
            flags = [f for f in char.properties if f not in SECURITY_FLAGS]
            descs: list[tuple[str, list[str]]] = []
            for desc in char.descriptors:
                if str(desc.uuid) in BLUEZ_MANAGED_DESCRIPTORS:
                    continue
                # Bleak doesn't expose descriptor flags on all backends;
                # read+write covers standard discovery needs
                descs.append((str(desc.uuid), ["read", "write"]))
            svc_info.chars.append(
                CharInfo(uuid=str(char.uuid), flags=flags, handle=char.handle, descriptors=descs)
            )

        services.append(svc_info)

    log.info(f"Enumerated {len(services)} service(s).")
    return EnumResult(
        device_name=client.address,  # caller overwrites with device.name
        service_uuids=service_uuids,
        services=services,
    )
