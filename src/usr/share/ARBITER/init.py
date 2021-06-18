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

init.py, starts Daemon service with configuration files.
"""

import configparser
import main
from ast import literal_eval

config_handler = configparser.ConfigParser()
config_handler.read("/etc/ARBITER/init.cfg")

if __name__ == "__main__":
    key = config_handler["security"]["key"]
    if key.lower() == "none":
        key = None
    network_bits = config_handler["debug"]["network_bits"]
    if network_bits == "None":
        network_bits = None
    else:
        network_bits = int(network_bits)
    main.Daemon(key, literal_eval(config_handler["security"]["key_is_path"]),
                int(config_handler["server"]["port"]),
                config_handler["server"]["host"],
                literal_eval(config_handler["debug"]["no_listen_on_init"]),
                network_bits, literal_eval(config_handler["herder"]["enable"]),
                int(config_handler["herder"]["workers"]))
