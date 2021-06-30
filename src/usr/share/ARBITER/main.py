"""
ARBITER.

 ▄▄▄       ██▀███   ▄▄▄▄    ██▓▄▄▄█████▓▓█████  ██▀███
▒████▄    ▓██ ▒ ██▒▓█████▄ ▓██▒▓  ██▒ ▓▒▓█   ▀ ▓██ ▒ ██▒
▒██  ▀█▄  ▓██ ░▄█ ▒▒██▒ ▄██▒██▒▒ ▓██░ ▒░▒███   ▓██ ░▄█ ▒
░██▄▄▄▄██ ▒██▀▀█▄  ▒██░█▀  ░██░░ ▓██▓ ░ ▒▓█  ▄ ▒██▀▀█▄
 ▓█   ▓██▒░██▓ ▒██▒░▓█  ▀█▓░██░  ▒██▒ ░ ░▒████▒░██▓ ▒██▒
 ▒▒   ▓▒█░░ ▒▓ ░▒▓░░▒▓███▀▒░▓    ▒ ░░   ░░ ▒░ ░░ ▒▓ ░▒▓░
  ▒   ▒▒ ░  ░▒ ░ ▒░▒░▒   ░  ▒ ░    ░     ░ ░  ░  ░▒ ░ ▒░
  ░   ▒     ░░   ░  ░    ░  ▒ ░  ░         ░     ░░   ░
      ░  ░   ░      ░       ░              ░  ░   ░

Made by perpetualCreations

Probably flexible enough for daemons to be modularized into separate server \
    instances, for meshes.
Probably.
"""

import sqlite3
import socket
import sys
import threading
from hashlib import md5
from typing import Callable, Union, Literal
from os import remove, path, rename
from concurrent.futures import ThreadPoolExecutor
from ipaddress import IPv4Address, IPv4Network
from subprocess import call
from time import time, sleep
import nmap3
import swbs

# constants, mostly for lookups.
NETWORK_CLASSES = [IPv4Network(("10.0.0.0", "255.0.0.0")),
                   IPv4Network(("172.16.0.0", "255.240.0.0")),
                   IPv4Network(("192.168.0.0", "255.255.0.0"))]
LOOKUP_NETWORK_CLASS_TO_BITS = {NETWORK_CLASSES[0]: 8, NETWORK_CLASSES[1]: 16,
                                NETWORK_CLASSES[2]: 24}
LOOKUP_BITS_TO_NETWORK_CLASS = {8: "10.0.0.0", 16: "172.16.0.0",
                                24: "192.168.0.0"}
LOOKUP_DIRECTIVE_TYPE_TO_FILE_EXTENSION = {"SCRIPT": ".txt",
                                           "APPLICATION": ".py"}


class Exceptions:
    """Parent class of all exceptions."""

    class ClientManagerException(BaseException):
        """A Daemon.ClientManager thread has raised a general exception."""

    class DatabaseManagerException(BaseException):
        """A Daemon.DatabaseManager instance has raised a \
            general exception."""


class Daemon(swbs.Server):
    """Main application class."""

    def __init__(self, key: Union[str, bytes, None], key_is_path: bool = False,
                 port: int = 999, host: str = "localhost",
                 no_listen_on_init: bool = False,
                 network_bits: Union[None, int] = 24,
                 herder_start_on_init: bool = True, herder_workers: int = 2):
        """Application initialization."""
        self.client_tracker = Daemon.ClientTracker(self)
        self.herder = Daemon.Herder(port, key, self, key_is_path, network_bits,
                                    herder_start_on_init, herder_workers)
        self.database_manager = \
            Daemon.DatabaseManager("/etc/ARBITER/agency.db")
        super().__init__(port, key, Daemon.ClientManager, host, key_is_path,
                         no_listen_on_init)

    def get_client_manager_by_uuid(self, uuid: str) \
            -> Union[Daemon.ClientManager, None]:
        """
        Get ClientManager instance by UUID.

        :return: ClientManager instance with matching UUID, None if failed
        :rtype: Union[Daemon.ClientManager, None]
        """
        for client in self.clients:
            if self.clients[client]["thread"].agent_uuid == \
                    uuid:
                return self.clients[client]["thread"]
        return None

    class ClientManager(
            swbs.ServerClientManagers.ClientManagerInstanceExposed):
        """
        ARBITER client manager, handles incoming clients along their \
            life-cycle.

        Executed as a thread by Daemon listening thread.

        Accepts KINETIC and FORESIGHT clients. FORESIGHT clients have no start
            and stop controls, and the client handler loop will continue
            forever until the Daemon is stopped.
        """

        def __init__(self, instance: Daemon,
                     connection_socket: Union[socket.socket, object],
                     client_id: int):
            """Initialize manager."""
            self.application_thread = None
            self.event_stop_directive = threading.Event()
            self.event_start_directive = threading.Event()
            self.agent_uuid: str = "None"
            self.client_type: str = "None"
            self.is_foresight_updater: bool = False
            super().__init__(instance, connection_socket, client_id)

        def process(self) -> None:
            """Start actual execution."""
            self.event_stop_directive.clear()
            self.event_start_directive.clear()
            Daemon.ClientManager.send(self, "REQUEST TYPE")
            self.client_type = Daemon.ClientManager.receive(self)
            if self.client_type == "FORESIGHT":
                self.agent_uuid = "FORESIGHT"
                commands = {
                    "ADD_AGENT": lambda: self.payload_handler(
                        Daemon.Herder.herd_target, self.instance.herder),
                    "REMOVE_AGENT": lambda: self.payload_handler(
                        Daemon.DatabaseManager.remove_agent,
                        self.instance.database_manager),
                    "ADD_DIRECTIVE": lambda: print("NOT IMPLEMENTED!"),
                    "REMOVE_DIRECTIVE": lambda: self.payload_handler(
                        Daemon.DatabaseManager.remove_directive,
                        self.instance.database_manager)
                }
                while True:
                    if self.is_foresight_updater is False:
                        request = Daemon.ClientManager.receive(self)
                        if request == "UPDATE":
                            self.is_foresight_updater = True
                            Daemon.ClientManager.send(self, "OK")
                            continue
                        try:
                            Daemon.ClientManager.send(self, str(
                                commands[request]()))
                        except KeyError:
                            Daemon.ClientManager.send(self, "KEYERROR")
                    else:
                        while True not in [self.instance.database_manager.
                                           database_updated_event.is_set(),
                                           self.instance.client_tracker.
                                           connected_uuids_update_event.
                                           is_set(), self.instance.herder.
                                           add_agent_outcome_event.is_set()]:
                            pass
                        if self.instance.herder.add_agent_outcome_event.\
                                is_set() is True:
                            Daemon.ClientManager.send(self, "add-agent STATE")
                            Daemon.ClientManager.receive(self)
                            Daemon.ClientManager.send(
                                self, str(self.instance.herder.
                                          add_agent_outcome).lower())
                            self.instance.herder.add_agent_outcome_event.\
                                clear()
                        # remove NID from table data
                        table_contents = self.instance.database_manager.\
                            get_all_agents()
                        for index, _dummy in enumerate(table_contents):
                            # remove numeric id column
                            table_contents[index].remove(0)
                            # index 0 now is the UUID column
                            # evaluate whether UUID is in connected agents list
                            # expression returns True/False, eliminates the
                            # need for a conditional
                            table_contents[index].append((
                                table_contents[index][0] in self.instance.
                                client_tracker.connected_uuids))
                        # transmit table data for agents-table
                        Daemon.ClientManager.send(
                            self, "agents-table-content TABLE")
                        Daemon.ClientManager.receive(self)
                        Daemon.ClientManager.send(
                            self, str(table_contents))
                        # transmit table data for directives-table
                        Daemon.ClientManager.send(
                            self, "directives-table-content")
                        Daemon.ClientManager.receive(self)
                        Daemon.ClientManager.send(
                            self, str(self.instance.database_manager.
                                      get_all_directives()))
                        self.instance.database_manager.\
                            database_updated_event.clear()
                        self.instance.client_tracker.\
                            connected_uuids_update_event.clear()
            elif self.client_type == "KINETIC":
                pass
            else:
                Daemon.ClientManager.send(self, "ABORT")
                del self.instance.clients[self.client_id]
                self.connection_socket.close()
                raise Exceptions.ClientManagerException(
                    "Client is not a KINETIC agent or FORESIGHT interface. "
                    "Stopped ClientManager instance.")
            Daemon.ClientManager.send(self, "REQUEST UUID")
            self.agent_uuid = self.instance.network.receive(
                socket_instance=self.connection_socket)
            if self.instance.database_manager.get_agent(
                    self.agent_uuid) is None:
                self.instance.database_manager.add_agent(self.agent_uuid)
            else:
                directives = self.instance.database_manager.\
                    parse_directives(self.agent_uuid)
                if directives is None:
                    return
                elif isinstance(directives, list) is True:
                    index = 0
                    while index > len(directives):
                        if self.event_stop_directive.is_set() is True:
                            # probably unsafe for the agent, since the script
                            # can stop during execution
                            # TODO add option for safe stop user-defined script
                            break
                        if directives[index].split(" ")[0] == "GOTO":
                            try:
                                index = min(max(int(
                                    directives[index].split(" ")[1]), 0),
                                            len(directives) - 1)
                            except IndexError:
                                pass
                            except ValueError:
                                pass
                        elif directives[index][:3] == "-#-":
                            index += 1
                        else:
                            Daemon.ClientManager.send(self, directives[index])
                            index += 1
                        continue
                else:
                    self.application_thread = \
                        threading.Thread(target=directives.Application,
                                         args={"instance": self.instance,
                                               "connection_socket":
                                                   self.connection_socket,
                                                   "client_id": self.client_id,
                                                   "uuid": self.agent_uuid,
                                                   "stop_event":
                                               self.event_stop_directive})
                    self.application_thread.start()
                    self.event_stop_directive.wait()
                    # noinspection PyUnresolvedReferences
                    # self.application_thread is a threading.Thread object,
                    # default None under the conditions presented in current
                    # scope, it will always be a thread from this context
                    self.application_thread.join()

        def run(self) -> None:
            """
            Threading execution and handling.

            :return: None
            """
            while True:
                Daemon.ClientManager.process(self)
                self.event_start_directive.wait()

        def send(self, message: Union[str, bytes]) -> None:
            """
            SWBS send wrapper, to specify socket_instance as \
                self.connection_socket.

            :param message: Union[str, bytes], message to be sent
            :return: None
            """
            Daemon.send(self.instance, message, self.connection_socket)

        def receive(self, buffer_size: int = 4096,
                    return_bytes: bool = False) -> Union[str, bytes]:
            """
            SWBS receive wrapper, to specify socket_instance as \
                self.connection_socket.

            :param buffer_size: int, size of buffer for received bytes
            :param return_bytes: bool, if True received bytes are not
                decoded to unicode string, default False
            :return: Union[str, bytes], message received
            """
            return Daemon.receive(self.instance, buffer_size,
                                  self.connection_socket, return_bytes)

        def payload_handler(self, target: Callable, target_instance) -> None:
            """
            Handle payload requests from the web front-end.

            :param target: function to call with payload data
            :type target: Callable
            :param target_instance: instance parameter to call target with,
                set None for no instance parameter
            """
            Daemon.ClientManager.send(self, "OK")
            if target_instance is None:
                target(Daemon.ClientManager.receive(self))
            else:
                target(target_instance, Daemon.ClientManager.receive(self))

    class ClientTracker:
        """With every client connection, processes client dictionary to \
            procure a list with the UUIDs of all agents connected to the \
                ARBITER server."""

        def __init__(self, outer_self: Daemon):
            """
            Initialize tracker.

            :param outer_self: outer Daemon instance reference
            :type outer_self: Daemon
            :ivar self.outer_self: dump of parameter outer_self
            :ivar self.thread: process thread
            :ivar self.client_connect_event: threading Event object set with
                client connects and disconnects
            :ivar self.connected_uuids_update_event: threading Event object set
                when ClientTracker has just finished a parsing loop
            :ivar self.connected_uuids: list of agents by UUID that are
                connected
            """
            self.outer_self = outer_self
            self.connected_uuids: list = []
            self.connected_uuids_update_event: threading.Event = \
                threading.Event()
            self.client_connect_event: threading.Event = threading.Event()
            self.client_connect_event.set()
            self.thread = threading.Thread(
                target=Daemon.ClientTracker.process,
                args=(self,), daemon=True)
            self.thread.start()

        def process(self) -> None:
            """Loop infinitely while parsing client dictionary."""
            while True:
                self.client_connect_event.wait()
                self.connected_uuids.clear()
                for client in self.outer_self.clients:
                    if self.outer_self.clients[client]["threading"].\
                            agent_uuid == "FORESIGHT":
                        continue
                    self.connected_uuids.append(
                        self.outer_self.clients[client]["threading"].
                        agent_uuid)
                self.client_connect_event.clear()
                self.connected_uuids_update_event.set()

    class Herder(swbs.Client):
        """Searches for lost agents, as a shepard would find lost sheep."""

        def __init__(self, port: int, key: Union[str, bytes, None],
                     outer_self: Daemon, key_is_path: bool = False,
                     bits: Union[None, int] = 24, start_on_init: bool = True,
                     workers: int = 2):
            """Thread initialization."""
            self.outer_self = outer_self
            host = "0.0.0.0"
            super().__init__(host, port, key, key_is_path)
            if bits not in range(0, 25):
                bits = None
            self.bits = bits
            if bits is None:
                self.bits = 24
                for classes in NETWORK_CLASSES:
                    if IPv4Address(socket.gethostbyname(socket.gethostname()
                                                        )) in classes:
                        self.bits = LOOKUP_NETWORK_CLASS_TO_BITS[classes]
                        break
            self.client_lock = threading.Lock()
            self.add_agent_outcome: bool = False
            self.add_agent_outcome_event = threading.Event()
            self.thread_pool = \
                ThreadPoolExecutor(workers, "arbiter_daemon_herder_thread_")
            self.thread_kill_flag: bool = False
            if start_on_init is True:
                Daemon.Herder.start(self)

        def start(self) -> None:
            """
            Start executing thread pool.

            Stop execution with Daemon.Herder.kill().
            """
            self.thread_kill_flag = False
            self.thread_pool.submit(Daemon.Herder.thread)

        def kill(self) -> None:
            """
            Kill threads and close the thread pool executor, freeing resources.

            Start execution again with Daemon.Herder.start().
            """
            self.thread_kill_flag = True
            self.thread_pool.shutdown(False)

        # noinspection PyBroadException
        def thread(self) -> None:
            """Scan for lost agents with NMAP, and signal them to a \
                controller."""
            mapper = nmap3.NmapHostDiscovery()
            while self.thread_kill_flag is False:
                results = mapper.nmap_no_portscan(
                    LOOKUP_BITS_TO_NETWORK_CLASS[self.bits] + "/" +
                    str(self.bits))
                results.pop("stats")
                results.pop("runtime")
                self.client_lock.acquire(True)
                for result in list(results.keys()):
                    self.host = result
                    # pylint: disable=broad-except
                    try:
                        Daemon.Herder.connect(self)
                        if Daemon.Herder.receive(self) == \
                                "KINETIC WAITING FOR CONTROLLER":
                            Daemon.Herder.send(self, "POINT " +
                                               socket.gethostname() + ".local")
                        else:
                            Daemon.Herder.disconnect(self)
                    except BaseException:
                        Daemon.Herder.disconnect(self)
                self.client_lock.release()

        def herd_target(self, target: str) -> None:
            """
            Attempt to refer specific host to ARBITER.

            :param target: hostname of target
            :type target: str
            """
            self.client_lock.acquire(True)
            self.add_agent_outcome = False
            try:
                self.host = target
                Daemon.Herder.connect(self)
                if Daemon.Herder.receive(self) == \
                        "KINETIC WAITING FOR CONTROLLER":
                    Daemon.Herder.send(self, "POINT " +
                                       socket.gethostname() + ".local")
                    self.add_agent_outcome = True
            # more warcrimes!
            # pylint: disable=broad-except
            except BaseException:
                pass
            finally:
                Daemon.Herder.disconnect(self)
            self.client_lock.release()
            self.add_agent_outcome_event.set()

    class DatabaseManager:
        """SQLite3 database manager, that handles I/O operations."""

        def __init__(self, file: str):
            """Initialize Manager class."""
            self.connection = sqlite3.connect(file)
            self.cursor = self.connection.cursor()
            try:
                self.cursor.execute("SELECT * FROM agents")
            except sqlite3.OperationalError:
                self.cursor.execute("CREATE TABLE agents (nid INTEGER NOT NULL"
                                    " PRIMARY KEY AUTOINCREMENT, uuid TEXT "
                                    "NOT NULL, name TEXT, directive_id "
                                    "INTEGER)")
                self.connection.commit()
            try:
                self.cursor.execute("SELECT * FROM directives")
            except sqlite3.OperationalError:
                self.cursor.execute("CREATE TABLE directives (nid INTEGER NOT "
                                    "NULL PRIMARY KEY AUTOINCREMENT, name TEXT"
                                    " NOT NULL, type TEXT NOT NULL, pypi BOOL "
                                    "NOT NULL)")
                self.connection.commit()
            self.database_updated_event = threading.Event()
            # set on init so table population occurs upon first connect
            self.database_updated_event.set()

        @staticmethod
        def sanitize(uuid: str) -> str:
            """
            Sanitize UUID if not standard UUID.

            :param uuid: agent UUID, must be alphanumeric,
                hyphens/dashes are allowed, no spaces (as standard UUIDs should
                be), non-standard UUIDs that disobey this specification will be
                normalized through MD5 hashing
            :type uuid: str
            :return: UUID or hash of disallowed non-standard UUID
            :rtype: str
            """
            # up for scrutiny, is this adequate sanitation?
            # failsafe in case the given uuid is empty, create hash from
            # current time
            if len(uuid) == 0:
                uuid = str(time())
                sleep(1)
            uuid = uuid.replace(" ", "")
            if uuid.replace("-", "").isalnum() is False:
                uuid = md5(uuid.encode("ascii")).hexdigest()
            return uuid

        def add_agent(self, uuid: str, directive: Union[int, None]) -> None:
            """
            Add agent to database. If agent already exists, overwrites.

            :param uuid: agent UUID, must be alphanumeric, hyphens/dashes
                are allowed, no spaces (as standard UUIDs should be),
                non-standard UUIDs that disobey this specification will be
                normalized through MD5 hashing
            :type uuid: str
            :param directive: numeric ID of directive for agent to be assigned
                to, or None for agent to not be assigned initially to any
                known directive
            :type directive: Union[int, None]
            """
            uuid = self.sanitize(uuid)
            try:
                if self.get_agent(uuid) is None:
                    self.cursor.execute("DELETE FROM agents WHERE uuid = " +
                                        uuid)
                self.cursor.execute("INSERT INTO agents (uuid, directive_id) "
                                    "VALUES (:uuid, :directive)",
                                    {"uuid": uuid, "directive": directive})
                self.connection.commit()
            except sqlite3.OperationalError as parent_exception:
                raise Exceptions.DatabaseManagerException(
                    "Failed to add entry for (UUID) " + uuid + ".") \
                        from parent_exception
            self.database_updated_event.set()

        def add_directive(self, name: str, content: Union[str, None],
                          directive_type: Literal["SCRIPT", "APPLICATION"],
                          is_pypi: bool) -> None:
            """
            Add directive with given parameters.

            Will add both a database entry script file,
            or PIP application installation.

            :param name: name of directive, must be a valid filename unless
                parameter is_pypi is True, in which case this parameter should
                be the application package name to be installed from PyPI
            :type name: str
            :param content: content of directive script or application, unless
                parameter is_pypi is True, in which case this parameter should
                be the application import name (ran through python -m)
            :type content: str
            :param directive_type: type of directive, valid types are SCRIPT
                and APPLICATION
            :type directive_type: Literal["SCRIPT", "APPLICATION"]
            :param is_pypi: whether directive is to be installed from PyPI,
                only is effective if directive_type is APPLICATION.
            :type is_pypi: bool
            """
            if is_pypi is True and directive_type != "APPLICATION":
                is_pypi = False
            try:
                self.cursor.execute("INSERT INTO directives (name, type, pypi)"
                                    " VALUES (:name, :type, :pypi)",
                                    {"name": name, "type": directive_type,
                                     "pypi": is_pypi})
                self.connection.commit()
            except sqlite3.OperationalError as parent_exception:
                raise Exceptions.DatabaseManagerException(
                    "Failed to add entry for (directive) " + name + ".") \
                        from parent_exception
            if is_pypi is False:
                with open("/etc/ARBITER/directives/" + name +
                          LOOKUP_DIRECTIVE_TYPE_TO_FILE_EXTENSION[
                              directive_type], "w") as directive_file_handle:
                    directive_file_handle.write(content)
            else:
                call("sudo python3 -m pip install " + name, shell=True)
            self.database_updated_event.set()

        def remove_agent(self, uuid: str) -> None:
            """
            Remove agent from database.

            :param uuid: agent UUID, must be alphanumeric, hyphens/dashes
                are allowed, no spaces (as standard UUIDs should be),
                non-standard UUIDs that disobey this specification will be
                normalized through MD5 hashing
            :type uuid: str
            """
            uuid = self.sanitize(uuid)
            try:
                self.cursor.execute(
                    "DELETE FROM agents WHERE uuid=:uuid", {"uuid": uuid})
                self.connection.commit()
            except sqlite3.OperationalError as parent_exception:
                raise Exceptions.DatabaseManagerException(
                    "Failed to remove agent entry for (UUID) " + uuid + ".") \
                        from parent_exception
            self.database_updated_event.set()

        def remove_directive(self, nid: int) -> None:
            """
            Remove directive by integer ID.

            Will delete both its database entry and script file,
            or PIP application installation.

            :param nid: numeric ID number of the directive
            :type nid: int
            """
            if self.get_directive(nid)[3] == 0:
                remove("/etc/ARBITER/directives/" + self.get_directive(nid)[1]
                       + LOOKUP_DIRECTIVE_TYPE_TO_FILE_EXTENSION[
                           self.get_directive(nid)[2]])
            else:
                call("sudo python3 -m pip uninstall " +
                     self.get_directive(nid)[1], shell=True)
            self.cursor.execute("DELETE FROM directives WHERE nid=:nid",
                                {"nid": nid})

        def edit_agent(self, uuid: str, mod: dict) -> None:
            """
            Edit agent in database.

            :param uuid: agent UUID, must be alphanumeric, hyphens/dashes
                are allowed, no spaces (as standard UUIDs should be),
                non-standard UUIDs that disobey this specification will be
                normalized through MD5 hashing
            :type uuid: str
            :param mod: should contain modifications to agent row, specify
                "directive_id" or "name" (case-sensitive) as keys being the
                columns to be overwritten, the values attached to keys being
                the new value of the column, to clear directive or name set
                them to None
            :type mod: dict
            """
            uuid = self.sanitize(uuid)
            try:
                for key in mod:
                    if key in ["directive_id", "name"]:
                        self.cursor.execute(
                            "UPDATE agents SET " + key + "=:value" +
                            " WHERE uuid=:uuid", {"uuid": uuid,
                                                  "value": mod[key]})
                self.connection.commit()
            except sqlite3.OperationalError as parent_exception:
                raise Exceptions.DatabaseManagerException(
                    "Failed to edit agent entry for (UUID) " + uuid + ".") \
                    from parent_exception
            self.database_updated_event.set()

        def edit_directive(self, nid: int, mod: dict) -> None:
            """
            Edit directive in database.

            :param nid: numeric ID of directive
            :type nid: str
            :param mod: should contain modifications to agent row, specify
                "name" or "type", (case-sensitive) as keys being the columns
                to be overwritten, the values attached to keys being the new
                value of the column, columns cannot be cleared
            :type mod: dict
            """
            # pypi mod is disabled. overly complicates everything.
            rename("/etc/ARBITER/directives/" + self.get_directive(nid)[1]
                   + LOOKUP_DIRECTIVE_TYPE_TO_FILE_EXTENSION[
                       self.get_directive(nid)[2]],
                   "/etc/ARBITER/directives/" + mod.get(
                       "name", self.get_directive(nid)[1])
                   + LOOKUP_DIRECTIVE_TYPE_TO_FILE_EXTENSION[
                       mod.get("type", self.get_directive(nid)[2])])
            try:
                for key in mod:
                    if key in ["name", "type"]:
                        self.cursor.execute(
                            "UPDATE agents SET " + key + "=:value" +
                            " WHERE nid=:nid", {"nid": nid, "value": mod[key]})
                self.connection.commit()
            except sqlite3.OperationalError as parent_exception:
                raise Exceptions.DatabaseManagerException(
                    "Failed to edit directive entry for (NID) " + nid + ".") \
                    from parent_exception
            self.database_updated_event.set()

        def get_agent(self, uuid: str) -> tuple:
            """
            Get agent record in database.

            :param uuid: agent UUID, must be alphanumeric, hyphens/dashes are
                allowed, no spaces (as standard UUIDs should be), non-standard
                UUIDs that disobey this specification will be normalized
                through MD5 hashing
            :type uuid: str
            :return: database row for agent entry
            :rtype: tuple
            """
            return self.cursor.execute("SELECT * FROM agents WHERE uuid=:uuid",
                                       {"uuid": self.sanitize(uuid)}
                                       ).fetchone()

        def get_all_agents(self) -> list:
            """
            Get ALL agents from database.

            :return: all rows from agents database table
            :rtype: list
            """
            return list(self.cursor.execute("SELECT * FROM agents").fetchall())

        def get_directive(self, nid: int) -> tuple:
            """
            Get directive record in database.

            :param nid: numeric ID of directive
            :type nid: int
            :return: database row for directive entry
            :rtype: tuple
            """
            return self.cursor.execute("SELECT * FROM directives WHERE "
                                       "nid=:nid", {"nid": nid}).fetchone()

        def get_all_directives(self) -> list:
            """
            Get ALL agents from database.

            :return: all rows from directives database table
            :rtype: list
            """
            return list(self.cursor.execute(
                "SELECT * FROM directives").fetchall())

        def parse_directives(self, uuid: str) -> Union[list, object, None]:
            """
            Parse directives for agent by UUID.

            :param uuid: agent UUID, must be alphanumeric, hyphens/dashes are
                allowed, no spaces (as standard UUIDs should be), non-standard
                UUIDs that disobey this specification will be normalized
                through MD5 hashing
            :type uuid: str
            :return: None if no directive is registered, returns list with
                commands if directive is a script, returns Python module if
                directive is an application
            :rtype: Union[list, object, None]
            """
            entry = self.get_agent(uuid)
            if entry is None:
                raise Exceptions.DatabaseManagerException(
                    "Entry for (UUID) " + uuid + " does not exist.")
            if entry[2] is not None:
                if entry[3] == "SCRIPT":
                    # noinspection PyBroadException
                    try:
                        with open(entry[2]) as script_handle:
                            return script_handle.read().split("\n")
                    except BaseException as parent_exception:
                        raise Exceptions.DatabaseManagerException(
                            "Failed to interpret script directive.") \
                            from parent_exception
                elif entry[3] == "APPLICATION":
                    sys.path.append(path.split(entry[2])[0])
                    target = None
                    # FIXME application script importing
                    exec("import " + path.splitext(path.split(entry[2])[1])[0]
                         + " as target")
                    return target
