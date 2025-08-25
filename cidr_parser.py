from dataclasses import dataclass, field
from typing import List
import ipaddress

@dataclass
class CIDRParser:
    cidr_dict: dict[str,str] = field(default_factory=dict)

    def add_cidr(self, cidr, customer:''):
        cidr = cidr.strip(' ').strip('\n')
        if self.is_address(cidr) or self.is_network(cidr):
            self.cidr_dict[cidr] = customer
        else:
            raise ValueError(f"Invalid cidr {cidr}")
    

    def contains(self, ip: str) -> bool:
        """Verifica si una IP está dentro de alguno de los CIDRs."""
        ip_obj = ipaddress.ip_address(ip)
        return any(ip_obj in network for network in self.cidr_networks)


    @classmethod
    def is_address(cls, valor: str) -> bool:
        try:
            ipaddress.ip_address(valor)
            return True
        except ValueError:
            return False


    @classmethod
    def is_network(cls, valor: str) -> bool:
        try:
            net = ipaddress.ip_network(valor,strict=False)
            if net.prefixlen == 32 or net.prefixlen == 128:
                raise ValueError("Not red")
            return True
        except ValueError:
            return False


    @classmethod
    def split_cidr(cls, cidr, minMask):
        if ':' in cidr:
            cidr = ipaddress.IPv6Network(cidr.strip('\n'), strict=False)
        else:
            cidr = ipaddress.IPv4Network(cidr.strip('\n'), strict=False)
        if int(minMask) <= cidr.prefixlen:
            return [cidr.with_prefixlen]
        try:   
            return [net.with_prefixlen for net in cidr.subnets(new_prefix=int(minMask))]
        except Exception as e:
            print(cidr,e)
            return []
