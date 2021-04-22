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

Configuration
-------------
TODO, stage not applicable.

Scripts
-------
ARBITER uses a custom scripting language, called NAVSCRIPT. The script file is in plaintext, and should exist in the OS file system ARBITER is running on, to be executed.

Please see `preliminary documentation </projects/spec_providence/docs/NAVSCRIPT.html>`_ for more information regarding this language.

Applications
------------
In addition to scripts, ARBITER accepts Python modules. Specify a Python script file on the OS file system as a directive.

ARBITER expects there to be a class called "Application" with parameters for instance, connection_socket, client_id, and uuid.
The first three are the same parameters for swbs.ServerClientManagers.ClientManager derivatives. As such, they also share the same types.
The fourth is the agent UUID, as a string.

ARBITER will then initialize the "Application" class with those parameters, executing anything in the __init__ function of the class.
