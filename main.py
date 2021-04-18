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
import socket
import nmap3
import sqlite3
from hashlib import md5
from typing import Union
from ipaddress import IPv4Address, IPv4Network
from concurrent.futures import ThreadPoolExecutor


class Exceptions:
    """
    Parent class of all exceptions.
    """

    class ClientManagerException(BaseException):
        """
        A Daemon.ClientManager thread has raised a general exception.
        """

    class DirectivesManagerException(BaseException):
        """
        A Daemon.DirectivesManager instance has raised a general exception.
        """


class Daemon(swbs.Server):
    """
    Main application class.
    """

    def __init__(self, key: Union[str, bytes, None], key_is_path: bool = False, port: int = 999,
                 host: str = "localhost", no_listen_on_init: bool = False, network_bits: int = 24,
                 herder_start_on_init: bool = True, herder_workers: int = 2):
        """
        Application initialization.
        """
        self.herder = Daemon.Herder(port, key, key_is_path, network_bits, herder_start_on_init, herder_workers)
        super().__init__(port, key, Daemon.ClientManager, host, key_is_path, no_listen_on_init)

    class Herder(swbs.Client):
        """
        Searches for lost agents, as a shepard would find lost sheep.
        """

        def __init__(self, port: int, key: Union[str, bytes, None], key_is_path: bool = False,
                     bits: Union[None, int] = 24, start_on_init: bool = True, workers: int = 2):
            """
            Thread initialization.
            """
            host = "0.0.0.0"
            super().__init__(host, port, key, key_is_path)
            if bits not in range(0, 25):
                bits = None
            self.bits = bits
            if bits is None:
                NETWORK_CLASSES = [IPv4Network(("10.0.0.0", "255.0.0.0")), IPv4Network(("172.16.0.0", "255.240.0.0")),
                                   IPv4Network(("192.168.0.0", "255.255.0.0"))]
                LOOKUP = {NETWORK_CLASSES[0]: 8, NETWORK_CLASSES[1]: 16, NETWORK_CLASSES[2]: 24}
                for classes in NETWORK_CLASSES:
                    if IPv4Address(socket.gethostbyname(socket.gethostname())) in classes:
                        self.bits = LOOKUP[classes]
                        break
                self.bits = 24
            self.thread_pool = ThreadPoolExecutor(workers, "arbiter_daemon_herder_thread_")
            self.thread_kill_flag = False
            if start_on_init is True:
                Daemon.Herder.start(self)

        def start(self) -> None:
            """
            Start executing thread pool.
            Stop execution with Daemon.Herder.kill().

            :return: None
            """
            self.thread_kill_flag = False
            self.thread_pool.submit(Daemon.Herder.thread)

        def kill(self) -> None:
            """
            Kill threads and close the thread pool executor, freeing resources.
            Start execution again with Daemon.Herder.start().

            :return: None
            """
            self.thread_kill_flag = True
            self.thread_pool.shutdown(False)

        # noinspection PyBroadException
        def thread(self) -> None:
            """
            Scan for lost agents with NMAP, and signal them to a controller.

            :return: None
            """
            mapper = nmap3.NmapHostDiscovery()
            LOOKUP = {8: "10.0.0.0", 16: "172.16.0.0", 24: "192.168.0.0"}
            while self.thread_kill_flag is False:
                results = mapper.nmap_no_portscan(LOOKUP[self.bits] + "/" + str(self.bits))
                results.pop("stats")
                results.pop("runtime")
                for result in list(results.keys()):
                    self.host = result
                    try:
                        Daemon.Herder.connect(self)
                        if Daemon.Herder.receive(self) == "KINETIC WAITING FOR CONTROLLER":
                            Daemon.Herder.send(self, "POINT " + socket.gethostname() + ".local")
                        else:
                            Daemon.Herder.disconnect(self)
                    except BaseException:
                        Daemon.Herder.disconnect(self)

    class DirectivesManager:
        """
        SQLite3 database manager, that handles I/O operations to and from the directives database.
        """
        # TODO awaiting implementation
        directive_type_flag = None
        directive_path_flag = None
        null_flag = None

        def __init__(self, file: str):
            """
            Manager initialization.
            """
            self.connection = sqlite3.connect(file)
            self.cursor = self.connection.cursor()
            try:
                self.cursor.execute("SELECT * FROM agents")
            except sqlite3.OperationalError:
                self.cursor.execute("CREATE TABLE agents (nid INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, "
                                    "uuid TEXT NOT NULL, directive_path TEXT, directive_type TEXT)")
                self.connection.commit()
            pass

        @staticmethod
        def sanitize(uuid: str) -> str:
            """
            Sanitize UUID if not standard UUID.

            :param uuid: str, agent UUID, must be alphanumeric, hyphens/dashes are allowed, no spaces (as standard
                UUIDs should be), non-standard UUIDs that disobey this specification will be normalized through MD5
                hashing
            :return: str, UUID or hash of disallowed non-standard UUID
            """
            # up for scrutiny, is this adequate sanitation?
            uuid = uuid.replace(" ", "")
            if uuid.replace("-", "").isalnum() is False:
                uuid = md5(uuid.encode("ascii")).hexdigest()
            return uuid

        def add_agent(self, uuid: str, directive_type: Union[str, None] = None,
                      directive_path: Union[str, None] = None) -> None:
            """
            Add agent to database. If agent already exists, overwrites.

            :param uuid: str, agent UUID, must be alphanumeric, hyphens/dashes are allowed, no spaces (as standard
                UUIDs should be), non-standard UUIDs that disobey this specification will be normalized through MD5
                hashing
            :param directive_type: str, type of directive, valid types are SCRIPT and APPLICATION, if None no directive
                is registered, and no directive will be assigned to the agent, has cross-dependency with directive_path
                requiring both to be not None and defined to have a record registered, default None
            :param directive_path: str, path to directive, being Python module or script text file, if None no directive
                is registered, and no directive will be assigned to the agent, has cross-dependency with directive_path
                requiring both to be not None and defined to have a record registered, default None
            :return: None
            """
            uuid = "'" + Daemon.DirectivesManager.sanitize(uuid) + "'"
            if directive_path is None or directive_type is None:
                directive_path = ":null"
                directive_type = ":null"
            else:
                directive_path = "'" + directive_path + "'"
                directive_type = "'" + directive_type + "'"
            try:
                self.cursor.execute("INSERT INTO agents (uuid, directive_path, directive_type) VALUES (" + uuid + ", " +
                                    directive_path + ", " + directive_type + ")", {"null": None})
                self.connection.commit()
            except sqlite3.OperationalError:
                self.cursor.execute("DELETE FROM agents WHERE uuid = '" + uuid + "'")
                self.cursor.execute("INSERT INTO agents (uuid, directive_path, directive_type) VALUES (" + uuid + ", " +
                                    directive_path + ", " + directive_type + ")", {"null": None})
                self.connection.commit()

        def remove_agent(self, uuid: str) -> None:
            """
            Remove agent from database.

            :param uuid: str, agent UUID, must be alphanumeric, hyphens/dashes are allowed, no spaces (as standard
                UUIDs should be), non-standard UUIDs that disobey this specification will be normalized through MD5
                hashing
            :return: None
            """
            uuid = Daemon.DirectivesManager.sanitize(uuid)
            try:
                self.cursor.execute("DELETE FROM agents WHERE uuid = '" + uuid + "'")
                self.connection.commit()
            except sqlite3.OperationalError as ParentException:
                raise Exceptions.DirectivesManagerException("Failed to remove agent entry for (UUID) " + uuid + ".") \
                    from ParentException

        def edit_agent(self, uuid: str, mod: dict) -> None:
            """
            Edit agent in database.

            :param uuid: str, agent UUID, must be alphanumeric, hyphens/dashes are allowed, no spaces (as standard
                UUIDs should be), non-standard UUIDs that disobey this specification will be normalized through MD5
                hashing
            :param mod: dict, should contain modifications to agent row, specify "uuid", "directive_path", and
                "directive_type" (case-sensitive) as keys being the columns to be overwritten, the output assigned to
                keys being the new value of the column, example {"directive_path":"/home/hokma/directives.txt"}, to
                clear directive_path or directive_type set them to "NULL" or None
            :return: None
            """
            uuid = Daemon.DirectivesManager.sanitize(uuid)
            # piped into SQL execution
            settings = ""
            for column in list(mod.keys()):
                if column not in ["uuid", "directive_path", "directive_type"]:
                    mod.pop(column)
                    continue
                if column in ["directive_path", "directive_type"] and mod[column] in ["NULL", None]:
                    settings += column + " = :null, "
                    continue
                settings += column + " = '" + mod[column] + "', "
            settings = settings.rstrip(", ")
            try:
                self.cursor.execute("UPDATE agents SET " + settings + " WHERE uuid = '" + uuid + "';", {"null": None})
                self.connection.commit()
            except sqlite3.OperationalError as ParentException:
                raise Exceptions.DirectivesManagerException("Failed to edit agent entry for (UUID) " + uuid + ".") \
                    from ParentException

        def get_agent(self, uuid: str) -> tuple:
            """
            Get agent record in database.

            :return: tuple, database row for agent entry
            """
            uuid = Daemon.DirectivesManager.sanitize(uuid)
            return self.cursor.execute("SELECT * FROM agents WHERE uuid = '" + uuid + "';").fetchone()

        def get_all_agents(self) -> list:
            """
            Get ALL agents from database.

            :return: tuple, database row for agent entry
            """
            return self.cursor.execute("SELECT * FROM agents").fetchall()

        def parse_directive(self, uuid: str) -> any:
            """
            Parse directives for agent by UUID.

            :return: dict
            """
            entry = Daemon.DirectivesManager.get_agent(self, uuid)

    class ClientManager(swbs.ServerClientManagers.ClientManager):
        """
        ARBITER client manager, handles incoming clients along their life-cycle.
        Executed as a thread by Daemon listening thread.
        """

        def __init__(self, instance, connection_socket: Union[socket.socket, object], client_id: int):
            """
            Manager initialization.
            """
            super().__init__(instance, connection_socket, client_id)
            Daemon.ClientManager.send(self, "REQUEST TYPE")
            if Daemon.ClientManager.receive(self) != "KINETIC":
                del self.instance.clients[self.client_id]
                self.connection_socket.close()
                raise Exceptions.ClientManagerException("Client is not a KINETIC agent. Stopped ClientManager "
                                                        "instance.")
            self.instance.network.send("REQUEST UUID", self.connection_socket)
            self.agent_uuid = self.instance.network.receive(socket_instance=self.connection_socket)

        def send(self, message: Union[str, bytes], no_encrypt: bool = False) -> None:
            """
            SWBS send wrapper, to specify socket_instance as self.connection_socket.

            :param message: Union[str, bytes], message to be sent
            :param no_encrypt: bool, if True does not encrypt message, default False
            :return: None
            """
            Daemon.send(self.instance, message, self.connection_socket, no_encrypt)

        def receive(self, buffer_size: int = 4096, no_decrypt: bool = False, return_bytes: bool = False) -> \
                Union[str, bytes]:
            """
            SWBS receive wrapper, to specify socket_instance as self.connection_socket.

            :param buffer_size: int, size of buffer for received bytes
            :param no_decrypt: bool, if True does not decrypt message, default False
            :param return_bytes: bool, if True received bytes are not decoded to unicode string, default False
            :return: Union[str, bytes], message received
            """
            return Daemon.receive(self.instance, buffer_size, self.connection_socket, no_decrypt, return_bytes)
