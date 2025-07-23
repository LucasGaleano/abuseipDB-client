from dataclasses import dataclass, field
from typing import List
import ipaddress

@dataclass
class CIDRParser:
    cidr_strings: List[str]
    cidr_networks: List[ipaddress.IPv4Network] = field(init=False)

    def __init__(self, cidr_strings: List[str]):
        self.cidr_strings = []
        for cidr in cidr_strings:
            cidr = cidr.strip(' ').strip('\n')
            self.cidr_strings.append(cidr)
        self.__post_init__()  # llamado automáticamente

    def __post_init__(self):
        self.cidr_networks = []
        for cidr in self.cidr_strings:
            try:
                network = ipaddress.ip_network(cidr, strict=False)
                self.cidr_networks.append(network)
            except ValueError as e:
                raise ValueError(f"CIDR inválido: '{cidr}' - {e}")

    def contains(self, ip: str) -> bool:
        """Verifica si una IP está dentro de alguno de los CIDRs."""
        ip_obj = ipaddress.ip_address(ip)
        return any(ip_obj in network for network in self.cidr_networks)
