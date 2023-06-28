from unittest import TestCase
from unittest.mock import patch

from paramiko import ssh_exception
from paramiko.ssh_exception import AuthenticationException
from network.socket.ssh import ConnectSSH


class TestScan(TestCase):
    dummy_address = "1.1.1.1"

    # self.targets.send(failure)
    @patch.object(ConnectSSH, 'create_client')
    def test_agree_connect(self, mock_method):
        mock_method.return_value.connect.side_effect = [0, 0, 0, 0]
        ssh = ConnectSSH("127.0.0.1", verbose=True, username="user", passwords=["one", "two", "three", "four"],
                         wait_time=0.02)
        ssh.run()

        self.assertEqual(4, ssh.results.qsize())

    @patch.object(ConnectSSH, 'create_client')
    def test_agree_connect_fail(self, mock_method):
        mock_method.return_value.connect.side_effect = [ssh_exception.SSHException]
        ssh = ConnectSSH("127.0.0.1", verbose=True, username="user", passwords=["one", "two"], wait_time=0.02)
        self.assertIsNone(ssh.connect("user", "pass"))

        self.assertEqual(0, ssh.results.qsize())

    @patch.object(ConnectSSH, 'create_client')
    def test_connected(self, mock_method):
        mock_method.return_value.connect.side_effect = [0, 0]
        ssh = ConnectSSH("127.0.0.1", verbose=True, username="user", passwords=["one", "two"], wait_time=0.02)
        result = ssh.connect("user", "pass")
        self.assertTrue(result)
        self.assertEqual(1, ssh.results.qsize())

    @patch.object(ConnectSSH, 'create_client')
    def test_bad_pass(self, mock_method):
        mock_method.return_value.connect.side_effect = [AuthenticationException]
        ssh = ConnectSSH("127.0.0.1", verbose=True, username="user", passwords=["one", "two"], wait_time=0.02)
        self.assertFalse(ssh.connect("user", "pass"))
        self.assertEqual(0, ssh.results.qsize())

    @patch.object(ConnectSSH, 'create_client')
    def test_failures_retry(self, mock_method):
        mock_method.return_value.connect.side_effect = [ssh_exception.SSHException,
                                                        ssh_exception.SSHException,
                                                        ssh_exception.SSHException,
                                                        ssh_exception.SSHException,
                                                        ssh_exception.SSHException,
                                                        ssh_exception.SSHException,
                                                        ssh_exception.SSHException,
                                                        0, 0, 0, 0, 0, 0, 0
                                                        ]
        ssh = ConnectSSH("127.0.0.1", verbose=True, username="user", wait_time=0.02, max_threads=30,
                         passwords=["Fail 1",
                                    "Fail 2",
                                    "Fail 3",
                                    "Fail 4",
                                    "Fail 5",
                                    "Fail 6",
                                    "Fail 7"])
        ssh.run()
        self.assertEqual(7, ssh.results.qsize())

    @patch.object(ConnectSSH, 'create_client')
    def test_success_and_failures(self, mock_method):
        mock_method.return_value.connect.side_effect = [0,
                                                        AuthenticationException,
                                                        ssh_exception.SSHException,
                                                        ssh_exception.SSHException,
                                                        0,
                                                        0,
                                                        ssh_exception.SSHException,
                                                        0,
                                                        0,
                                                        0
                                                        ]
        ssh = ConnectSSH("127.0.0.1", verbose=True, username="user", wait_time=0.02, max_threads=1,
                         passwords=["Good 1",
                                    "bad auth",
                                    "Failed 1",
                                    "Failed 2",
                                    "Good 2",
                                    "Good 3",
                                    "Failed 3"])
        ssh.run()
        self.assertEqual(6, ssh.results.qsize())
