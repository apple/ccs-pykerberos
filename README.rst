PyKerberos Package
==================

.. image:: https://travis-ci.org/apple/ccs-pykerberos.svg?branch=master
    :target: https://travis-ci.org/apple/ccs-pykerberos

This Python package is a high-level wrapper for Kerberos (GSSAPI)
operations.  The goal is to avoid having to build a module that wraps
the entire Kerberos.framework, and instead offer a limited set of
functions that do what is needed for client/server Kerberos
authentication based on <http://www.ietf.org/rfc/rfc4559.txt>.

Much of the C-code here is adapted from Apache's mod_auth_kerb-5.0rc7.


Build
=====

In this directory, run:

  python setup.py build


Testing
=======

To run the tests in the tests folder, you must have a valid Kerberos setup on
the test machine. You can use the script .travis.sh as quick and easy way to
setup a Kerberos KDC and Apache web endpoint that can be used for the tests.
Otherwise you can also run the following to run a self contained Docker
container

.. code-block: bash

  docker run \
  -v $(pwd):/app \
  -w /app \
  -e PYENV=2.7.13 \
  -e KERBEROS_USERNAME=administrator \
  -e KERBEROS_PASSWORD=Password01 \
  -e KERBEROS_REALM=example.com \
  -e KERBEROS_PORT=80 \
  ubuntu:16.04 \
  /bin/bash .travis.sh

The docker command needs to be run in the same directory as this library and
you can test it with different Python versions by changing the value of the
PYENV environment value set in the command.

Please have a look at testing_notes.md for more information.


IMPORTANT
=========

The checkPassword method provided by this library is meant only for testing purposes as it does
not offer any protection against possible KDC spoofing. That method should not be used in any
production code.


Python APIs
===========

See kerberos.py.


Copyright and License
=====================

Copyright (c) 2006-2016 Apple Inc.  All rights reserved.

This software is licensed under the Apache License, Version 2.0.  The
Apache License is a well-established open source license, enabling
collaborative open source software development.

See the "LICENSE" file for the full text of the license terms.
