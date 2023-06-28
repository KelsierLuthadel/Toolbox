from dataclasses import dataclass
from enum import IntEnum


class PortType(IntEnum):
    TCP = 0
    UDP = 1


class PortStatus(IntEnum):
    OPEN = 0
    CLOSED = 1
    FILTERED = 2
    UNFILTERED = 3
    OPEN_FILTERED = 4
    CLOSED_FILTERED = 5


@dataclass
class Port:
    port_number: int
    port_type: PortType
    status: PortStatus
    status_code: int = None
    details: str = None
