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
cli.py, mimics a FORESIGHT instance to pass commands through.
"""

import configparser
from swbs import Client

config = configparser.ConfigParser()
config.read("/etc/ARBITER/init.cfg")
cli_client = Client(config["server"]["host"], int(config["server"]["port"]),
                    config["security"]["key"],
                    bool(config["security"]["key_is_path"]))
cli_client.connect()
if cli_client.receive() != "REQUEST TYPE":
    raise Exception("Failed to connect to ARBITER target.")
cli_client.send("FORESIGHT")
print("ARBITER CLI, v1.0\nReady for input. Type help for command list.")
while True:
    # pylint: disable=unnecessary-lambda, used-before-assignment
    # TODO insert commands here
    LOOKUP_COMMANDS = {
        "exit": lambda: exit(0),
        "help": lambda: print("Commands:", [x for x in LOOKUP_COMMANDS])
    }
    try:
        LOOKUP_COMMANDS[input("> ").lower()]()
    except KeyError:
        print("Invalid command.")
