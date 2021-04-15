"""
 ▄▄▄       ██▀███   ▄▄▄▄    ██▓▄▄▄█████▓▓█████  ██▀███
▒████▄    ▓██ ▒ ██▒▓█████▄ ▓██▒▓  ██▒ ▓▒▓█   ▀ ▓██ ▒ ██▒
▒██  ▀█▄  ▓██ ░▄█ ▒▒██▒ ▄██▒██▒▒ ▓██░ ▒░▒███   ▓██ ░▄█ ▒
░██▄▄▄▄██ ▒██▀▀█▄  ▒██░█▀  ░██░░ ▓██▓ ░ ▒▓█  ▄ ▒██▀▀█▄
 ▓█   ▓██▒░██▓ ▒██▒░▓█  ▀█▓░██░  ▒██▒ ░ ░▒████▒░██▓ ▒██▒
 ▒▒   ▓▒█░░ ▒▓ ░▒▓░░▒▓███▀▒░▓    ▒ ░░   ░░ ▒░ ░░ ▒▓ ░▒▓░
  ▒   ▒▒ ░  ░▒ ░ ▒░▒░▒   ░  ▒ ░    ░     ░ ░  ░  ░▒ ░ ▒░
  ░   ▒     ░░   ░  ░    ░  ▒ ░  ░         ░     ░░   ░
      ░  ░   ░      ░       ░              ░  ░   ░

ARBITER
Made by perpetualCreations
"""

import swbs
import configparser
from typing import Union
import nmap3
from ipaddress import IPv4Address, IPv4Network

class Daemon(swbs.Server):
    """
    Main application class.
    """
    def __init__(self, key: Union[str, bytes, None], key_is_path: bool = False, port: int = 999, host: str = "localhost"):
        """
        Application initialization.
        """
        super().__init__(port, key, Daemon.ClientManager, host, key_is_path)

    class Herder(swbs.Client):
        """
        Searches for lost agents, as a shepard would find lost sheep.
        """
        def __init__(self, port: int, key: Union[str, bytes, None], key_is_path: bool = False, bits: Union[None, int] = 24, thread_start_on_init: bool = False):
            """
            Thread initialization.
            """
            host = "0.0.0.0"
            super().__init__(host, port, key, key_is_path)
            if bits not in range(0, 25): bits = None
            self.bits = bits
            if bits is None:
                NETWORK_CLASSES = [IPv4Network(("10.0.0.0", "255.0.0.0")), IPv4Network(("172.16.0.0", "255.240.0.0")), IPv4Network(("192.168.0.0", "255.255.0.0"))]
                LOOKUP = {NETWORK_CLASSES[0]:8, NETWORK_CLASSES[1]:16, NETWORK_CLASSES[2]:24}
                for classes in NETWORK_CLASSES:
                    if socket.gethostbyname(socket.gethostname) in classes:
                        self.bits = LOOKUP[classes]
                        break
                self.bits = 24
            self.nmap = nmap3.NmapHostDiscovery()
            self.thread = None

        def scan(self) -> None:
            """
            Scan for lost agents with NMAP.

            :return: None
            """
            LOOKUP = {8:"10.0.0.0", 16:"172.16.0.0", 24:"192.168.0.0"}
            results = nmap.nmap_no_portscan(LOOKUP[self.bits] + "/" + str(self.bits))
            # analysis of results and signaling

    class ClientManager(swbs.ServerClientManagers.ClientManager):
        """
        ARBITER client manager, handles incoming clients along their life-cycle.
        """
        def __init__(self, instance, connection_socket: object, client_id: int):
            """
            Manager initialization.
            """
            super().__init__(instance, connection_socket, client_id)

