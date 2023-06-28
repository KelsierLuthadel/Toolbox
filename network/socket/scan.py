import itertools
import socket
import threading
import time
from queue import Queue
from queue import Empty

from network.inet.host import Host
from network.inet.inet_tools import read_ip, read_ports, get_hostname
from network.inet.model.address import NetAddress, IPFamily
from network.inet.model.port import Port, PortType, PortStatus

try:
    import resource
    resource.setrlimit(resource.RLIMIT_NOFILE, (4095, 4095))
except ModuleNotFoundError:
    pass  # Not supported in Windows


class Scan:
    default_ports = [22, 23, 80, 443]
    thread_limit = 4095

    def __init__(self, address, port=None, tcp=True,  wait_time=3, max_threads=500,
                 show_refused=False, show_banner=False, show_progress=True,
                 resolve_hostnames=False):
        self.ip_range = read_ip(address)

        if port is None:
            self.ports = Scan.default_ports
        else:
            self.ports = read_ports(port)

        if tcp:
            self.port_type = PortType.TCP
        else:
            self.port_type = PortType.UDP

        if wait_time <= 0:
            raise ValueError("Cannot have negative or zero wait time")

        self.wait_time = wait_time

        self.lock = threading.RLock()
        self.max_threads = max_threads

        if self.max_threads > Scan.thread_limit:
            self.max_threads = Scan.thread_limit

        self.show_refused = show_refused
        self.show_banner = show_banner
        self.show_progress = show_progress

        self.queue = Queue(maxsize=self.max_threads * 3)
        self.results = Host()

        self.connections = 0
        self.targets = None
        self.resolve_hostnames = resolve_hostnames

    def fill_queue(self):
        while True:
            if not self.queue.full():
                try:
                    self.queue.put(next(self.targets))
                    self.connections += 1
                except StopIteration:
                    # Break condition
                    break
            else:
                time.sleep(0.01)

    def worker(self):
        while True:
            try:
                work = self.queue.get()
                self.scan_port(*work)
            except Empty:
                return
            finally:
                self.queue.task_done()

    def create_socket(self):
        if self.port_type == PortType.TCP:
            return socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        else:
            return socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def connect(self, ip, port):
        sock = self.create_socket()
        sock.settimeout(self.wait_time)
        status = sock.connect_ex((ip, port))
        return sock, status

    def scan_port(self, ip, port):
        (sock, status) = self.connect(ip, port)

        details = self.get_banner(sock, status)

        self.show_port_status(details, ip, port, status)

        with self.lock:
            self.store_results(details, ip, port, status)

    def store_results(self, details, ip, port, status):
        if status == 0:
            connection_status = PortStatus.OPEN
        else:
            connection_status = PortStatus.CLOSED

        port_details = Port(port_number=port, port_type=self.port_type,
                            status=connection_status, status_code=status, details=details)
        if self.results.has_ip_address(ip) is False:
            net_address = NetAddress(address=ip, family=IPFamily.IP4)
            net_address.ports.append(port_details)
            self.results.add_address(net_address)
        else:
            self.results.add_port_to_host(ip_address=ip, port=port_details)

    def show_port_status(self, details, ip, port, status):
        if status == 0:
            with self.lock:
                if self.show_banner and details is not None:
                    if self.show_progress:
                        print(f'   {ip}:{port} OPEN: {details}')
                else:
                    if self.show_progress:
                        print(f'   {ip}:{port} OPEN')
        elif status not in [35, 64, 65]:
            if self.show_progress and self.show_refused:
                print(f'   {ip}:{port} CLOSED')

    def run(self):
        self.targets = ((ip, port) for ip in self.ip_range for port in self.ports)

        queue_thread = threading.Thread(target=self.fill_queue)
        queue_thread.daemon = True
        queue_thread.start()

        for _ in range(self.max_threads):
            t = threading.Thread(target=self.worker)
            t.daemon = True
            t.start()

        self.queue.join()

        if self.resolve_hostnames:
            print("\nResolving hostnames")
            self.resolve()

        print(f"\nScanned {self.connections} ports\n")

    def get_ordered_results(self):
        return list(sorted(self.results.address, key=lambda item: socket.inet_aton(item.address)))

    def count_open_ports(self, address: NetAddress):
        return len([port for port in address.ports if port.status == PortStatus.OPEN])

    def resolve(self):
        for address in self.results.address:
            if self.count_open_ports(address) > 0:
                address.hostname = get_hostname(address.address)

    def get_banner(self, sock, status):
        banner_text = None
        if status == 0 and self.show_banner:
            try:
                banner = sock.recv(1024)
                if banner is not None:
                    banner_text = banner.decode("utf-8").strip('\n\r')
            except OSError:
                banner_text = None

        return banner_text




