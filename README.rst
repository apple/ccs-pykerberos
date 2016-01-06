PyKerberos Package
==================

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

You must have a valid Kerberos setup on the test machine and you
should ensure that you have valid Kerberos tickets for any client
authentication being done (run 'klist' on the command line).
Additionally, for the server: it must have been configured as a valid
Kerberos service with the Kerbersos server for its realm - this
usually requires running kadmin on the server machine to add the
principal and generate a keytab entry for it (run 'sudo klist -k' to
see the currently available keytab entries).

Make sure that PYTHONPATH includes the appropriate build/lib.xxxx
directory.  Then run test.py with suitable command line arguments:

  python test.py -u userid -p password -s service
    
  -u
    user id for basic authenticate
  -p
    password for basic authenticate
  -s
    service principal for GSSAPI authentication (defaults to
    'http@host.example.com')


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
