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

web.py, handles running the web management application.
"""

import flask
import flask_login
import flask_socketio
import configparser
import json
import swbs
import threading
from os import urandom
from ast import literal_eval
from hashlib import sha3_512
from datetime import datetime, timezone


config = configparser.ConfigParser()
config.read("/etc/ARBITER/web.cfg")
arbiter_config = configparser.ConfigParser()
arbiter_config.read("/etc/ARBITER/init.cfg")
application = flask.Flask(__name__)
application.secret_key = urandom(4096)
login_manager = flask_login.LoginManager()
login_manager.init_app(application)
login_manager.login_view = "login"
users = {"username": "admin"}
socket_io = flask_socketio.SocketIO(application)

# all error messages get appended to this list, new clients will receive all
# error messages in list, to "catch them up"
errors: list = []
# dictionary overwritten when the directives database dispatches an update,
# sent to new clients instead of fetching database contents again
directives_database_cache: dict = {}


@socket_io.on("logError")
def log_error_broadcaster(message: str):
    """Emit event logError to all clients as a broadcast."""
    error = {"timestamp":
             datetime.utcnow().replace(tzinfo=timezone.utc).isoformat(),
             "message": message}
    errors.append(error)
    with application.app_context():
        flask_socketio.emit("logError", error, json=True, broadcast=True,
                            namespace="/")


class User(flask_login.UserMixin):
    """Flask user model."""


@login_manager.user_loader
def user_loader(user_id) -> User:
    """Flask Login function required for loading the admin user."""
    user = User()
    user.id = user_id
    return user


@socket_io.on("connect")
def connect_handler() -> any:
    """Handle websocket connections, checking for login auth."""
    if flask_login.current_user.is_authenticated is not True:
        return False
    else:
        with application.app_context():
            for error in errors:
                flask_socketio.emit("logError", error, json=True)
            flask_socketio.emit("eventUpdate", directives_database_cache,
                                json=True)


class InterfaceClient(swbs.Client):
    """Socket interface instance class."""

    def __init__(self, host, port, key, key_is_path):
        """Class initialization."""
        super().__init__(host, port, key, key_is_path)
        self.dead = False

    def connect_wrapper(self) -> None:
        """
        Serve as a wrapper for swbs.Client.connect.

        Has additional calls to specify ARIA protocol.
        """
        try:
            self.connect()
            type_request = self.receive()
            if type_request == "REQUEST TYPE":
                self.send("FORESIGHT")
                if self.receive() == "ABORT":
                    self.disconnect()
                    error_string = "Host " + self.host + " raised ABORT. " + \
                        "Interface client will shutdown."
                    self.dead = True
            else:
                InterfaceClient.send(self, "KEYERROR")
                InterfaceClient.disconnect()
                error_string = "Host " + self.host + \
                    " failed to send host request type, expected " + \
                    '"REQUEST TYPE"' + ", got " + type_request + "." + \
                    " Interface client will shutdown."
                print(error_string)
                log_error_broadcaster(error_string)
                self.dead = True
        except Exception as ParentException:
            error_string = "Failed to initialize interface host " + \
                "connecting to " + self.host + " on port " + str(self.port) + \
                ". Interface client will shutdown."
            print(str(ParentException) + " -> " + error_string)
            log_error_broadcaster(error_string)
            self.dead = True


def update_listener() -> None:
    """Thread for update events issued by the main ARBITER server."""
    set_update = False
    arbiter_updater_interface = \
        InterfaceClient("127.0.0.1", arbiter_config["server"]["port"],
                        arbiter_config["security"]["key"],
                        arbiter_config["security"]["key_is_path"])
    while arbiter_updater_interface.dead is \
            False:
        while flask_login.current_user is None:
            pass
        if set_update is False:
            arbiter_updater_interface.send("UPDATE")
            if arbiter_updater_interface.receive() == "OK":
                set_update = True
                continue
            else:
                error_string = "Host does not support event updating, " + \
                    "any display elements in the interfacce will not " + \
                    "update. Exiting listener."
                print(error_string)
                log_error_broadcaster(error_string)
                return None
        update_header_data = arbiter_updater_interface.receive().split(" ")
        if len(update_header_data) == 2 and \
                update_header_data[1] in ["STATE", "TABLE"]:
            arbiter_updater_interface.send("OK")
            update_content_data = \
                arbiter_updater_interface.receive()
            if update_header_data[1] == "TABLE":
                try:
                    update_content_data = literal_eval(update_content_data)
                except Exception as ParentException:
                    error_string = "Table data could not be interpreted, " + \
                        "raised exception: " + str(ParentException)
                    print(error_string)
                    log_error_broadcaster(error_string)
                    return None
                directives_database_cache = {"data": update_content_data,
                                             "id": update_header_data[0],
                                             "type": update_header_data[1]}
            with application.app_context():
                flask_socketio.emit("eventUpdate", directives_database_cache,
                                    json=True, broadcast=True)
            arbiter_updater_interface.send("OK")
        else:
            arbiter_updater_interface.send("KEYERROR")
            error_string = "Received update with invalid header, content: " + \
                str(update_header_data)
            print(error_string)
            log_error_broadcaster(error_string)


# interface inits
threading.Thread(target=update_listener, args=()).start()
arbiter_command_interface = \
    InterfaceClient("127.0.0.1", arbiter_config["server"]["port"],
                    arbiter_config["security"]["key"],
                    arbiter_config["security"]["key_is_path"])
arbiter_command_interface_lock = threading.Lock()


@socket_io.on("command")
def command_handler(json_payload) -> None:
    """Handle websocket command request events from clients."""
    json_payload = str(json_payload).replace("'", '"')
    command_payload = json.loads(json_payload)
    if arbiter_command_interface.dead is True:
        return None
    arbiter_command_interface_lock.acquire(True)
    if command_payload["requestType"] == "SIGNAL":
        arbiter_command_interface.send(command_payload["command"])
    elif command_payload["requestType"] == "PAYLOAD":
        arbiter_command_interface.send(command_payload["command"])
        if arbiter_command_interface.receive() == "KEYERROR":
            error_string = "Payload command " + \
                command_payload["command"] + " is invalid."
            print(error_string)
            log_error_broadcaster(error_string)
            arbiter_command_interface_lock.release()
            return None
        arbiter_command_interface.send(command_payload["payload"])
    else:
        error_string = "Received invalid requestType, expected " + \
            '"SIGNAL" or "PAYLOAD", got ' + \
            command_payload["requestType"] + ". Request ignored."
        print(error_string)
        log_error_broadcaster(error_string)
    arbiter_command_interface_lock.release()


@application.route("/")
@flask_login.login_required
def index() -> any:
    """
    Render index.html when root is requested.

    Serves as homepage with control panels.

    Requires login.

    :return: any
    """
    return flask.render_template("index.html", serverid=config["CORE"]["ID"])


@application.route("/password/", methods=["GET", "POST"])
@flask_login.login_required
def change_password() -> any:
    """
    Render change_password.html when requested with GET.

    Serves as utility page for changing the admin password.
    Validates and commits password change when requested with POST.
    Re-renders page with an error message if re-typed password is different.
    Requires login.

    :return: any
    """
    if flask.request.method == "GET":
        return flask.render_template("change_password.html",
                                     serverid=config["CORE"]["ID"], error="")
    elif flask.request.method == "POST":
        if flask.request.form["password"] == \
                flask.request.form["password_affirm"]:
            config["CORE"]["PASSWORD"
                           ] = sha3_512(
                               flask.request.form["password"
                                                  ].encode("ascii")
                                                  ).hexdigest()
            with open("main.cfg", "wb") as config_overwrite:
                config.write(config_overwrite)
            return flask.redirect(flask.url_for("index"))
        else:
            return flask.render_template("change_password.html",
                                         serverid=config["CORE"]["ID"],
                                         error="Passwords don't match.",
                                         form=flask.request.form)
    else:
        flask.abort(405)


@application.route("/login/", methods=["GET", "POST"])
def login() -> any:
    """
    Render login.html when requested with GET.

    Serves as login page for users to authenticate themselves.
    Validates password submissions when requested with POST,
    and redirects to root.
    Re-renders page with an error message if password is invalid
    when compared to hash.

    :return: any
    """
    if flask.request.method == "GET":
        if flask_login.current_user.is_authenticated is True:
            return flask.redirect(flask.url_for("index"))
        else:
            return flask.render_template("login.html",
                                         serverid=config["CORE"]["ID"],
                                         error="")
    elif flask.request.method == "POST":
        if sha3_512(flask.request.form["password"].encode("ascii", "replace")
                    ).hexdigest() == config["CORE"]["PASSWORD"]:
            user = User()
            user.id = users["username"]
            flask_login.login_user(user)
            return flask.redirect(flask.url_for("index"))
        else:
            return flask.render_template("login.html",
                                         serverid=config["CORE"]["ID"],
                                         error="Invalid password.")
    else:
        flask.abort(405)


@application.route("/logout/")
@flask_login.login_required
def logout() -> any:
    """
    Log out user session, and redirect to login page.

    Requires login.

    :return: any
    """
    flask_login.logout_user()
    return flask.redirect(flask.url_for("login"))


if __name__ == "__main__":
    socket_io.run(application, debug=literal_eval(config["CORE"]["DEBUG"]),
                  port=int(config["NET"]["PORT"]), use_reloader=False)
