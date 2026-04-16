"""Timestamped event and connection logging, mirrored to the session log file."""
import logging
from datetime import datetime

import state

log = logging.getLogger(__name__)


def log_event(direction: str, uuid: str, data: bytearray) -> None:
    """Log a GATT read/write/notify/forward event with a timestamp."""
    ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    line = f"[{ts}] {direction:4s}  UUID={uuid}  DATA={data.hex()}"
    print(line)
    if state.log_file:
        state.log_file.write(line + "\n")
        state.log_file.flush()


def log_connection(event: str, addr: str, extra: str = "") -> None:
    """Log a connection lifecycle event (connect, disconnect, service resolved)."""
    ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    line = f"[{ts}] {event:4s}  ADDR={addr}" + (f"  {extra}" if extra else "")
    log.info(line)
    if state.log_file:
        state.log_file.write(line + "\n")
        state.log_file.flush()
