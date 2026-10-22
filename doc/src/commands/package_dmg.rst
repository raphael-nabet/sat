
.. include:: ../../rst_prolog.rst

Command package_dmg
*******************

Description
============
The **package_dmg** command creates a macOS application bundle (``SALOME.app``)
and a disk image (``.dmg``) from the binaries of an application.
It is only available on macOS (Xcode Command Line Tools are required).

The bundle contains the same files as a binary package (``sat package --binaries``):
the installation directories of the products are copied into
``SALOME.app/Contents/Resources/BINARIES-<dist>/`` with the relative salome launcher.
``Contents/MacOS/SALOME`` runs this launcher with the embedded Python.

The binaries are made relocatable on any Mac:

* absolute dependencies outside the system are rewritten to ``@rpath/...``;
* libraries that do not belong to the application (e.g. the gcc runtime:
  ``libgfortran``, ``libquadmath``, ``libgcc_s``) are embedded in
  ``BINARIES-<dist>/_external/lib``;
* absolute ``LC_RPATH`` (the build directory) are removed and replaced by
  ``@loader_path`` relative rpaths;
* absolute symbolic links and absolute shebangs are fixed.

A verification step reports every dependency that does not resolve inside the bundle.

The bundle is not signed: the linker signatures of the binaries are kept and only
the invalid ones are re-signed ad hoc. Use *--sign_adhoc* to sign the whole bundle.
Notarization (Developer ID signature of every binary) is not done by this command.

Usage
=====
* Create ``SALOME.app`` and ``SALOME-<version>-<dist>-<arch>.dmg`` in ``<workdir>/PACKAGE``: ::

    sat package_dmg SALOME-master

* With a name, an icon, without the development files: ::

    sat package_dmg SALOME-master --name SALOME --icon salome.png --slim

* From an archive already produced by ``sat package --binaries``: ::

    sat package_dmg SALOME-master --archive SALOME-master-MACOS15.tar.gz

* Only the bundle, replacing an existing one: ::

    sat package_dmg SALOME-master --no_dmg --replace

.. note::
   When launched from the Finder, the output of SALOME is written in
   ``~/Library/Logs/<name>/<name>.log``.

   Binaries that cannot be modified (``not enough header space``) must be linked with
   ``-Wl,-headerpad_max_install_names``.

Some useful configuration paths
=================================

* **APPLICATION.workdir**: the default output directory is ``<workdir>/PACKAGE``.
* **APPLICATION.profile.launcher_name**: the name of the launcher run by the bundle.
