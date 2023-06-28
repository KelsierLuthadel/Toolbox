from network.inet.inet_tools import get_hostname
from network.inet.model.address import NetAddress
from network.inet.model.port import Port


class Host:
    def __init__(self, resolve=False):
        self.resolve = resolve
        self.address = []

    def add_address(self, address: NetAddress):
        if not self.has_ip_address(address.address):
            if self.resolve:
                address.hostname = get_hostname(address.address)
            self.address.append(address)
        else:
            print(f"[-]: {address.address} already exists")

    def has_ip_address(self, ip_address):
        return len(list(lookup for lookup in self.address if lookup.address == ip_address)) == 1

    def get_host_from_ip_address(self, ip_address):
        return next(lookup for lookup in self.address if lookup.address == ip_address)

    def get_hosts_from_hostname(self, hostname):
        return list(lookup for lookup in self.address if lookup.hostname == hostname)

    def host_has_port(self, host, port_number):
        return len(list(port for port in host.ports if port.port_number == port_number)) == 1

    def add_port_to_host(self, ip_address, port: Port):
        host = self.get_host_from_ip_address(ip_address)
        if not self.host_has_port(host, port.port_number):
            host.ports.append(port)
        else:
            print(f"Port {port.port_number} already exists in {host.address}")

