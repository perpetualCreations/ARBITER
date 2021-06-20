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

import swbs
import socket
import nmap3
import sqlite3
import sys
import threading
from hashlib import md5
from typing import Union
from ipaddress import IPv4Address, IPv4Network
from concurrent.futures import ThreadPoolExecutor
from os.path import splitext, split, isfile
from os import remove
from time import sleep
from typing import Callable, Union


class Exceptions:
    """Parent class of all exceptions."""

    class ClientManagerException(BaseException):
        """A Daemon.ClientManager thread has raised a general exception."""

    class DirectivesManagerException(BaseException):
        """A Daemon.DirectivesManager instance has raised a \
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
        self.directives_manager = \
            Daemon.DirectivesManager("/etc/ARBITER/agency.db")
        self.cli_queue_manager = Daemon.CLIQueueManager(self)
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
                COMMAND_LOOKUP = {
                    "ADD_AGENT": lambda: self.payload_handler(
                        Daemon.Herder.herd_target, self.instance.herder)
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
                                COMMAND_LOOKUP[request]()))
                        except KeyError:
                            Daemon.ClientManager.send(self, "KEYERROR")
                    else:
                        while True not in [self.instance.directives_manager.
                                           directives_updated_event.is_set(),
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
                        table_contents = self.instance.directives_manager.\
                            get_all_agents()
                        for index in range(len(table_contents)):
                            # remove numeric id column
                            table_contents[index].remove(0)
                            # index 0 now is the UUID column
                            # evaluate whether UUID is in connected agents list
                            # expression returns True/False, eliminates the
                            # need for a conditional
                            table_contents[index].append((
                                table_contents[index][0] in self.instance.
                                client_tracker.connected_uuids))
                        Daemon.ClientManager.send(
                            self, "agents-table-content TABLE")
                        Daemon.ClientManager.receive(self)
                        Daemon.ClientManager.send(
                            self, str(table_contents))
                        self.instance.directives_manager.\
                            directives_updated_event.clear()
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
            if self.instance.directives_manager.get_agent(
                    self.agent_uuid) is None:
                self.instance.directives_manager.add_agent(self.agent_uuid)
            else:
                directives = self.instance.directives_manager.\
                    parse_directives(self.agent_uuid)
                if directives is None:
                    return
                elif type(directives) is list:
                    index = 0
                    while index > len(directives):
                        if self.event_stop_directive.is_set() is True:
                            # probably unsafe for the agent, since the script
                            # can stop during execution
                            # but we'll just slap on a bright yellow warning
                            # to end users issuing directive stops
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
                NETWORK_CLASSES = [IPv4Network(("10.0.0.0", "255.0.0.0")),
                                   IPv4Network(("172.16.0.0", "255.240.0.0")),
                                   IPv4Network(("192.168.0.0", "255.255.0.0"))]
                LOOKUP = {NETWORK_CLASSES[0]: 8, NETWORK_CLASSES[1]: 16,
                          NETWORK_CLASSES[2]: 24}
                for classes in NETWORK_CLASSES:
                    if IPv4Address(socket.gethostbyname(socket.gethostname()
                                                        )) in classes:
                        self.bits = LOOKUP[classes]
                        break
                self.bits = 24
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
            LOOKUP = {8: "10.0.0.0", 16: "172.16.0.0", 24: "192.168.0.0"}
            while self.thread_kill_flag is False:
                results = mapper.nmap_no_portscan(LOOKUP[self.bits] + "/" +
                                                  str(self.bits))
                results.pop("stats")
                results.pop("runtime")
                self.client_lock.acquire(True)
                for result in list(results.keys()):
                    self.host = result
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
                else:
                    Daemon.Herder.disconnect(self)
            except BaseException:
                Daemon.Herder.disconnect(self)
            self.client_lock.release()
            self.add_agent_outcome_event.set()

    class DirectivesManager:
        """SQLite3 database manager, that handles I/O operations to and from \
            the directives database."""

        def __init__(self, file: str):
            """Initialize Manager class."""
            self.connection = sqlite3.connect(file)
            self.cursor = self.connection.cursor()
            try:
                self.cursor.execute("SELECT * FROM agents")
            except sqlite3.OperationalError:
                self.cursor.execute("CREATE TABLE agents (nid INTEGER NOT NULL"
                                    " PRIMARY KEY AUTOINCREMENT, uuid TEXT "
                                    "NOT NULL, name TEXT, directive_path TEXT,"
                                    " directive_type TEXT)")
                self.connection.commit()
            self.directives_updated_event = threading.Event()
            # set on init so table population occurs upon first connect
            self.directives_updated_event.set()

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
            uuid = uuid.replace(" ", "")
            if uuid.replace("-", "").isalnum() is False:
                uuid = md5(uuid.encode("ascii")).hexdigest()
            return uuid

        def add_agent(self, uuid: str, directive_type: Union[str, None] = None,
                      directive_path: Union[str, None] = None) -> None:
            """
            Add agent to database. If agent already exists, overwrites.

            :param uuid: agent UUID, must be alphanumeric, hyphens/dashes
                are allowed, no spaces (as standard UUIDs should be),
                non-standard UUIDs that disobey this specification will be
                normalized through MD5 hashing
            :type uuid: str
            :param directive_type: type of directive, valid types are
                SCRIPT and APPLICATION, if None no directive is registered,
                and no directive will be assigned to the agent, has
                cross-dependency with directive_path requiring both to be not
                None and defined to have a record registered, default None
            :type directive_type: str
            :param directive_path: path to directive, being Python module
                or script text file, if None no directive is registered, and
                no directive will be assigned to the agent, has
                cross-dependency with directive_path requiring both to be not
                None and defined to have a record registered, default None
            :type directive_path: str
            """
            uuid = "'" + Daemon.DirectivesManager.sanitize(uuid) + "'"
            if directive_path is None or directive_type is None:
                directive_path = ":null"
                directive_type = ":null"
            else:
                directive_path = "'" + directive_path + "'"
                directive_type = "'" + directive_type + "'"
            try:
                if Daemon.DirectivesManager.get_agent(self, uuid) is None:
                    self.cursor.execute("DELETE FROM agents WHERE uuid = " +
                                        uuid)
                self.cursor.execute("INSERT INTO agents (uuid, directive_path,"
                                    "directive_type) VALUES (" + uuid + ", " +
                                    directive_path + ", " + directive_type +
                                    ")", {"null": None})
                self.connection.commit()
            except sqlite3.OperationalError as ParentException:
                raise Exceptions.DirectivesManagerException("Failed to add "
                                                            "entry for (UUID) "
                                                            + uuid + ".") \
                    from ParentException
            self.directives_updated_event.set()

        def remove_agent(self, uuid: str) -> None:
            """
            Remove agent from database.

            :param uuid: agent UUID, must be alphanumeric, hyphens/dashes
                are allowed, no spaces (as standard UUIDs should be),
                non-standard UUIDs that disobey this specification will be
                normalized through MD5 hashing
            :type uuid: str
            """
            uuid = Daemon.DirectivesManager.sanitize(uuid)
            try:
                self.cursor.execute("DELETE FROM agents WHERE uuid = '" + uuid
                                    + "'")
                self.connection.commit()
            except sqlite3.OperationalError as ParentException:
                raise Exceptions.DirectivesManagerException(
                    "Failed to remove agent entry for (UUID) " + uuid + ".") \
                        from ParentException
            self.directives_updated_event.set()

        def edit_agent(self, uuid: str, mod: dict) -> None:
            """
            Edit agent in database.

            :param uuid: agent UUID, must be alphanumeric, hyphens/dashes
                are allowed, no spaces (as standard UUIDs should be),
                non-standard UUIDs that disobey thisspecification will be
                normalized through MD5 hashing
            :type uuid: str
            :param mod: should contain modifications to agent row, specify
                "uuid", "directive_path", "directive_type", and/or "name",
                (case-sensitive) as keys being the columns to be overwritten,
                the output assigned to keys being the new value of the column,
                example {"directive_path":"/home/hokma/directives.txt"}, to
                clear directive_path or directive_type set them to "NULL" or
                None
            :type mod: dict
            """
            uuid = Daemon.DirectivesManager.sanitize(uuid)
            # piped into SQL execution
            settings = ""
            for column in mod:
                if column not in ["uuid", "directive_path", "directive_type",
                                  "name"]:
                    mod.pop(column)
                    continue
                if column in ["directive_path", "directive_type", "name"] and \
                        mod[column] in ["NULL", None]:
                    settings += column + " = :null, "
                    continue
                settings += column + " = '" + mod[column] + "', "
            settings = settings.rstrip(", ")
            try:
                self.cursor.execute("UPDATE agents SET " + settings +
                                    " WHERE uuid = '" + uuid + "';",
                                    {"null": None})
                self.connection.commit()
            except sqlite3.OperationalError as ParentException:
                raise Exceptions.DirectivesManagerException(
                    "Failed to edit agent entry for (UUID) " + uuid + ".") \
                    from ParentException
            self.directives_updated_event.set()

        def get_agent(self, uuid: str) -> tuple:
            """
            Get agent record in database.

            :param uuid: str, agent UUID, must be alphanumeric, hyphens/dashes
                are allowed, no spaces (as standard UUIDs should be),
                non-standard UUIDs that disobey this specification will be
                normalized through MD5 hashing
            :return: tuple, database row for agent entry
            """
            uuid = Daemon.DirectivesManager.sanitize(uuid)
            return self.cursor.execute("SELECT * FROM agents WHERE uuid = '" +
                                       uuid + "';").fetchone()

        def get_all_agents(self) -> list:
            """
            Get ALL agents from database.

            :return: database row for agent entry
            :rtype: list
            """
            return self.cursor.execute("SELECT * FROM agents").fetchall()

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
            entry = Daemon.DirectivesManager.get_agent(self, uuid)
            if entry is None:
                raise Exceptions.DirectivesManagerException(
                    "Entry for (UUID) " + uuid + " does not exist.")
            if entry[2] is None or entry[3] is None:
                return None
            if entry[3] == "SCRIPT":
                # noinspection PyBroadException
                try:
                    with open(entry[2]) as script_handle:
                        return script_handle.read().split("\n")
                except BaseException as ParentException:
                    raise Exceptions.DirectivesManagerException(
                        "Failed to interpret script directive.") \
                        from ParentException
            if entry[3] == "APPLICATION":
                sys.path.append(split(entry[2])[0])
                target = None
                # FIXME application script importing
                exec("import " + splitext(split(entry[2])[1])[0] +
                     " as target")
                return target

    class CLIQueueManager:
        """Manages incoming commands from /etc/ARBITER/queue."""

        def __init__(self, outer_self: Daemon):
            """
            Initialize manager.

            :param outer_self: outer Daemon instance reference
            :type outer_self: Daemon
            :ivar self.outer_self: dump of parameter outer_self
            :ivar self.thread: process thread
            """
            self.outer_self = outer_self
            self.thread = threading.Thread(
                target=Daemon.CLIQueueManager.process,
                args=(self,), daemon=True)
            self.thread.start()

        def process(self) -> None:
            """Process through queue contents."""
            while True:
                if isfile("/etc/ARBITER/queue_lock") is True:
                    sleep(1)
                else:
                    with open("/etc/ARBITER/queue_lock") as lock_handler:
                        lock_handler.write("\x00")
                    with open("/etc/ARBITER/queue") as queue_handler:
                        queue = queue_handler.read()
                        queue = queue.split("\n")
                        for command in queue:
                            if command[:3] == "-#-":
                                continue
                            components = command.split("<#>")
                            LOOKUP = {"directive_assign": lambda: self.
                                      outer_self.directives_manager.
                                      edit_agent(self.outer_self.
                                                 directives_manager,
                                                 components[1],
                                                 {"directive_type":
                                                     components[2],
                                                     "directive_path":
                                                         components[3]}),
                                      "directive_start":
                                          lambda: Daemon.
                                          get_client_manager_by_uuid(
                                              self.outer_self,
                                              components[1]).
                                          event_start_directive.set(),
                                          "directive_stop":
                                              lambda: Daemon.
                                              get_client_manager_by_uuid(
                                                  self.outer_self,
                                                  components[1]).
                                              event_stop_directive.set()}
                            LOOKUP[components[0]]()
                    with open("/etc/ARBITER/queue", "w") as \
                            queue_overwrite_handler:
                        queue_overwrite_handler.write(
                            "-#- This is the queue file, any CLI operations "
                            "get dumped here for ARBITER to parse. "
                            "Robots only.")
                    remove("/etc/ARBITER/queue_lock")
