"""Specifies Installed-Size in Debian package control file."""

from pathlib import Path

# https://stackoverflow.com/questions/1392413/calculating-a-directorys-size-using-python
# high-level development: I now have an API and StackOverflow copy-paste addiction
root_directory = Path("src")
disk_size = sum(f.stat().st_size for f in root_directory.glob('**/*') if f.is_file())

with open("src/DEBIAN/control") as control_handler:
    origin = control_handler.read()
    origin = origin.split("\n")
    origin[6] = "Installed-Size: " + str(disk_size)
    with open("src/DEBIAN/control", "w") as writer:
        for line in origin:
            writer.write(line + "\n")
