Python 3 Linux Daemon for Managing KINETIC Agents
=================================================
:Latest Version - |version|:

.. toctree::
   :maxdepth: 2
   :caption: Contents:

Indices and tables
------------------
* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
* `Back to Projects </index.html##projects>`_

Install
-------
ARBITER can be installed with APT or manually installed with a Debian package file.
Please see `preliminary documentation </index.html###ppa>`_ for how to add the PPA repository required for APT installation and updating.

.. code-block:: bash

   sudo apt install arbiter

.. parsed-literal::

   wget https://github.com/perpetualCreations/arbiter/releases/download/\ |release|\ /arbiter_\ |release|\ _all.deb
   sudo apt install /path/to/wheel/file/arbiter_\ |release|\ _all.deb

.. |release| replace:: |version|

Outline
-------
ARBITER is a Linux server daemon written in Python 3, for Debian and Debian-based operating systems.

It manages KINETIC agents, through user-written directives that dictate orders for agents.

It's recommended to set the hostname of the server to ARBITER, see notes under section Herder for more information.

Configuration
-------------
Under the /etc/ARBITER/ directory is the init.cfg configuration file.

Inline comments document each field. Please refer to them for advisories and preliminary information.

Herder
------
KINETIC agents by default resolve the hostname "arbiter.local" for an ARBITER service, unless otherwise specified in init parameters.
Misconfiguration or the host operating system having a different hostname can result in agents being stranded, with no controller to operate them.

This is where Herder finds its purpose, looking for agents that weren't able to resolve their assigned ARBITER service.
It scans for ALL hosts on the network with NMAP, and tries to connect to any hosts that are up.

It will expect "KINETIC WAITING FOR CONTROLLER" to be sent by the client. If received, it continues on with pointing the client to the ARBITER host.
Otherwise, if the connection fails or this string is never received, Herder disconnects and moves onto the next host in the list.

This is obviously is problematic for certain deployments. See the init.cfg configuration file to disable Herder if needed.

Directives
----------
Directives are like orders given to a subordinate. They are two types of directives, scripts and applications.
One reads out with a line-by-line set of transmit-only commands to be sent, and the other is a full-fledged Python module, allowing for two-way communication and dynamic behavior.

Directives can be assigned through the CLI or web interface, with additional options for stop and start.
They are executed as soon as possible, upon the agent connecting to the ARBITER server.

See below for more information.

Scripts
-------
ARBITER uses a custom scripting language, called NAVSCRIPT. The script file is in plaintext, and should exist in the OS file system ARBITER is running on, to be executed.

Scripts can be subject to being suddenly terminated, if an end-user manually stops a script before it finishes executing.
Please keep this in mind when writing scripts, and interpret this as a warning against indiscriminately issuing manual directive stops.
Also consider designing your custom KINETIC `ARIA commands </projects/spec_providence/docs/ARIA.html>`_ to be tolerant to sudden stops.

Please see `preliminary documentation </projects/spec_providence/docs/NAVSCRIPT.html>`_ for more information regarding this language.

Applications
------------
In addition to scripts, ARBITER accepts Python modules. Specify a Python script file on the OS file system as a directive.

Applications are executed on a separate Daemon thread.
**They may be requested to be abruptly terminated, when directives are stopped, restarted, or overwritten.**
Please see sections below regarding how to respect this software behavior in your application.
Without it, **your application directive will be unmanageable, unless another exit condition executes itself**.

ARBITER expects there to be a class called "Application" with parameters for instance, connection_socket, client_id, uuid, and stop_event.
The first three are the same parameters for swbs.ServerClientManagers.ClientManager derivatives. As such, they also share the same types.
The fourth is the agent UUID, as a string.
The fifth is the stop thread event, a threading.Event object. When set, it signals for the application to stop.

ARBITER will then initialize the "Application" class with those parameters, executing anything in the __init__ function of the class.

The stop_event threading.Event object can be accessed with .is_set(), returning True if it has been set.
Use a conditional in your code to check for the event to be set, whether during execution or on a child thread.
Include instructions for graceful termination in the conditional.

Alternatively, use a child thread with the .wait() function, blocking execution until set.
Write instructions for safely exiting after the blocking wait call.

Interfaces
----------
ARBITER has a CLI and web interface, the latter provided by Project FORESIGHT.

The command-line interface can be accessed through command arbiter-manage.
See arbiter-manage --help for a list of commands and their usage.
