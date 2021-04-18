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

unit test for Daemon.DirectivesManager SQl database management
"""

import main
from time import time

init_time = time()

# initialization test
manager = main.Daemon.DirectivesManager("example.db")
# addition test
manager.add_agent("2332db7f-ab93-4b75-9a20-b963756cff94", "APPLICATION", "/dev/null/")
print(manager.get_agent("2332db7f-ab93-4b75-9a20-b963756cff94"))
# addition overwrite test
manager.add_agent("2332db7f-ab93-4b75-9a20-b963756cff94", "APPLICATION", "/home/binah/scripture/main.py")
print(manager.get_agent("2332db7f-ab93-4b75-9a20-b963756cff94"))
# edit test
manager.edit_agent("2332db7f-ab93-4b75-9a20-b963756cff94", {"directive_type": "APPLICATION",
                                                            "directive_path": "/dev/null/"})
print(manager.get_agent("2332db7f-ab93-4b75-9a20-b963756cff94"))
# edit, uuid overwrite, set null test
manager.edit_agent("2332db7f-ab93-4b75-9a20-b963756cff94", {"uuid": "108a30e3-e8e4-4ecf-b9b0-72b6aef1adec",
                                                            "directive_type": None,
                                                            "directive_path": "NULL"})
print(manager.get_agent("108a30e3-e8e4-4ecf-b9b0-72b6aef1adec"))
# addition null test
manager.add_agent("b2b4c7cd-0c3f-4c8d-be06-c69a41e42fb7")
print(manager.get_agent("b2b4c7cd-0c3f-4c8d-be06-c69a41e42fb7"))
# remove test
manager.remove_agent("b2b4c7cd-0c3f-4c8d-be06-c69a41e42fb7")
# get all
print(manager.get_all_agents())

print("Completed in ", time() - init_time, " seconds.")
