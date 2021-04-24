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

cli.py, adds commands to /etc/ARBITER/queue for the main application instance to process.
"""

import argparse
import sqlite3
from os.path import isfile
from sys import exit
from os import remove

parser = argparse.ArgumentParser()
parser.add_argument("operation", help="Operation to be committed to queue for ARBITER to process. Valid types are "
                                      "directive_assign, directive_start, directive_stop, and list_agents. directive_* "
                                      "commands require --uuid to be specified, and directive_assign, --type and "
                                      "--path.")
parser.add_argument("--uuid", help="Agent UUID for assigning, starting, and stopping associated directive. Required for"
                                   " directive_* commands.")
parser.add_argument("--type", help="Directive type for assignment. Required for directive_assign. Valid types are "
                                   "script and application, non-case sensitive.")
parser.add_argument("--path", help="Path to script or application directive, for assignment. Required for "
                                   "directive_assign.")
arguments = parser.parse_args()

if arguments.operation not in ["directive_assign", "directive_start", "directive_stop", "list_agents"]:
    raise Exception("Invalid operation argument! See --help for valid commands.")

if arguments.operation == "list_agents":
    cursor = sqlite3.connect("/etc/ARBITER/agency.db").cursor()
    data = cursor.execute("SELECT * FROM agents").fetchall()
    # pretty risque
    for section in data:
        print(section)
    exit(0)

if arguments.uuid is None:
    raise Exception("UUID not specified for an operation that requires it! Specify agent ID with --uuid.")

if arguments.operation == "directive_assign":
    if arguments.type is None or arguments.path is None:
        raise Exception("Directive type or path not specified for an operation that requires it! Specify arguments with"
                        " --type and --path.")
    else:
        if isfile(arguments.path) is False:
            raise FileNotFoundError("Directive ", arguments.path, " does not exist.")
        arguments.type += "<#>"
        arguments.path += "<#>"
else:
    arguments.type = ""
    arguments.path = ""

while isfile("/etc/ARBITER/queue_lock") is True:
    # block execution until queue lock is freed
    pass

with open("/etc/ARBITER/queue_lock", "w") as lock_handle:
    lock_handle.write("\x00")

with open("/etc/ARBITER/queue", "a") as queue_handle:
    queue_handle.write(arguments.operation + "<#>" + arguments.uuid + "<#>" + arguments.type + arguments.path)

remove("/etc/ARBITER/queue_lock")
