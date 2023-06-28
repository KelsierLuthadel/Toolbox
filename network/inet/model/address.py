from dataclasses import dataclass, field
from enum import IntEnum
from typing import List, Optional

from network.inet.model.port import Port


class IPFamily(IntEnum):
    IP4 = 0
    IP6 = 1


@dataclass
class NetAddress:
    family: IPFamily
    address: str
    gateway: Optional[str] = None
    netmask:  Optional[str] = None
    mac_address:  Optional[str] = None
    broadcast:  Optional[str] = None
    hostname:  Optional[str] = None
    ports: List[Port] = field(default_factory=list)
