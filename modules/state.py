"""
Shared mutable proxy state.

All modules that need to read or write live proxy state import from here
instead of using module-level globals scattered across files.
"""
from __future__ import annotations

import asyncio
from typing import IO, TYPE_CHECKING

if TYPE_CHECKING:
    from bleak import BleakClient

# Keyed by BLE attribute handle (int), not UUID, to correctly disambiguate
# characteristics that share a UUID (e.g. multiple HID Report characteristics)
char_values: dict[int, bytearray] = {}
char_write_prefers_response: dict[int, bool] = {}

bleak_client: "BleakClient | None" = None
asyncio_loop: asyncio.AbstractEventLoop | None = None
log_file: IO | None = None
