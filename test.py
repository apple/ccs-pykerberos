#!/usr/bin/env python
##
# Copyright (c) 2006-2013 Apple Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
##

import kerberos
import getopt
import sys
import httplib
import socket
import ssl

"""
Examples:

sudo ./test.py -s HTTP@example.com service

sudo ./test.py -u user01 -p user01 -s HTTP@example.com -r EXAMPLE.COM basic

sudo ./test.py -s HTTP@example.com -r EXAMPLE.COM gssapi

./test.py -s HTTP@example.com -h calendar.example.com -p 8008 server

For the gssapi and server tests you will need to kinit a principal on the server first.

"""

def main():
    
    # Extract arguments
    user = ""
    pswd = ""
    service = "HTTP@EXAMPLE.COM"
    host = "host.example.com"
    realm ="HOST.EXAMPLE.COM"
    port = 8008
    use_ssl = False
    allowedActions = ("service", "basic", "gssapi", "server",)
    
    options, args = getopt.getopt(sys.argv[1:], "u:p:s:h:i:r:x")

    for option, value in options:
        if option == "-u":
            user = value
        elif option == "-p":
            pswd = value
        elif option == "-s":
            service = value
        elif option == "-h":
            host = value
        elif option == "-i":
            port = value
        elif option == "-r":
            realm = value
        elif option == "-x":
            use_ssl = True
    
    actions = set()
    for arg in args:
        if arg in allowedActions:
            actions.add(arg)
        else:
            print "Action not allowed: %s" % (arg,)
            sys.exit(1)
    
    # Get service principal
    if "service" in actions:
        print "\n*** Running Service Principal test"
        s, h = service.split("@")
        testServicePrincipal(s, h);

    # GSS Basic test
    if "basic" in actions:
        if (len(user) != 0) and (len(pswd) != 0):
            print "\n*** Running basic test"
            testCheckpassword(user, pswd, service, realm)
        else:
            print "\n*** Skipping basic test: no user or password specified"

    # Full GSSAPI test
    if "gssapi" in actions:
        print "\n*** Running GSSAPI test"
        testGSSAPI(service)

    if "server" in actions:
        print "\n*** Running HTTP test"
        testHTTP(host, port, use_ssl, service)

    print "\n*** Done\n"

def testServicePrincipal(service, hostname):
    try:
        result = kerberos.getServerPrincipalDetails(service, hostname)
    except kerberos.KrbError, e:
        print "Kerberos service principal for %s/%s failed: %s" % (service, hostname, e[0])
    else:
        print "Kerberos service principal for %s/%s succeeded: %s" % (service, hostname, result)

def testCheckpassword(user, pswd, service, realm):
    try:
        kerberos.checkPassword(user, pswd, service, realm)
    except kerberos.BasicAuthError, e:
        print "Kerberos authentication for %s failed: %s" % (user, e[0])
    else:
        print "Kerberos authentication for %s succeeded" % user

def testGSSAPI(service):
    def statusText(r):
        if r == 1:
            return "Complete"
        elif r == 0:
            return "Continue"
        else:
            return "Error"

    rc, vc = kerberos.authGSSClientInit(service);
    print "Status for authGSSClientInit = %s" % statusText(rc);
    if rc != 1:
        return
    
    rs, vs = kerberos.authGSSServerInit(service);
    print "Status for authGSSServerInit = %s" % statusText(rs);
    if rs != 1:
        return
    
    rc = kerberos.authGSSClientStep(vc, "");
    print "Status for authGSSClientStep = %s" % statusText(rc);
    if rc != 0:
        return
    
    rs = kerberos.authGSSServerStep(vs, kerberos.authGSSClientResponse(vc));
    print "Status for authGSSServerStep = %s" % statusText(rs);
    if rs == -1:
        return
    
    rc = kerberos.authGSSClientStep(vc, kerberos.authGSSServerResponse(vs));
    print "Status for authGSSClientStep = %s" % statusText(rc);
    if rc == -1:
        return

    print "Server user name: %s" % kerberos.authGSSServerUserName(vs);
    print "Server target name: %s" % kerberos.authGSSServerTargetName(vs);
    print "Client user name: %s" % kerberos.authGSSClientUserName(vc);
    
    rc = kerberos.authGSSClientClean(vc);
    print "Status for authGSSClientClean = %s" % statusText(rc);
    
    rs = kerberos.authGSSServerClean(vs);
    print "Status for authGSSServerClean = %s" % statusText(rs);

def testHTTP(host, port, use_ssl, service):

    class HTTPSConnection_SSLv3(httplib.HTTPSConnection):
        "This class allows communication via SSL."

        def connect(self):
            "Connect to a host on a given (SSL) port."

            sock = socket.create_connection((self.host, self.port), self.timeout)
            self.sock = ssl.wrap_socket(sock, self.key_file, self.cert_file, ssl_version=ssl.PROTOCOL_SSLv3)

    def sendRequest(host, port, ssl, method, uri, headers):
        response = None
        if use_ssl:
            http = HTTPSConnection_SSLv3(host, port)
        else:
            http = httplib.HTTPConnection(host, port)
        try:
            http.request(method, uri, "", headers)
            response = http.getresponse()
        finally:
            http.close()
        
        return response

    # Initial request without auth header
    uri = "/principals/"
    response = sendRequest(host, port, use_ssl, "OPTIONS", uri, {})
    
    if response is None:
        print "Initial HTTP request to server failed"
        return
    
    if response.status != 401:
        print "Initial HTTP request did not result in a 401 response"
        return
    
    hdrs = response.msg.getheaders("www-authenticate")
    if (hdrs is None) or (len(hdrs) == 0):
        print "No www-authenticate header in initial HTTP response."
    for hdr in hdrs:
        hdr = hdr.strip()
        splits = hdr.split(' ', 1)
        if (len(splits) != 1) or (splits[0].lower() != "negotiate"):
            continue
        else:
            break
    else:
        print "No www-authenticate header with negotiate in initial HTTP response."
        return        

    try:
        rc, vc = kerberos.authGSSClientInit(service=service);
    except kerberos.GSSError, e:
        print "Could not initialize GSSAPI: %s/%s" % (e[0][0], e[1][0])
        return

    try:
        kerberos.authGSSClientStep(vc, "");
    except kerberos.GSSError, e:
        print "Could not do GSSAPI step with continue: %s/%s" % (e[0][0], e[1][0])
        return

    hdrs = {}
    hdrs["Authorization"] = "negotiate %s" % kerberos.authGSSClientResponse(vc)    

    # Second request with auth header
    response = sendRequest(host, port, use_ssl, "OPTIONS", uri, hdrs)
    
    if response is None:
        print "Second HTTP request to server failed"
        return
    
    if response.status/100 != 2:
        print "Second HTTP request did not result in a 2xx response: %d" % (response.status,)
        return
    
    hdrs = response.msg.getheaders("www-authenticate")
    if (hdrs is None) or (len(hdrs) == 0):
        print "No www-authenticate header in second HTTP response."
        return
    for hdr in hdrs:
        hdr = hdr.strip()
        splits = hdr.split(' ', 1)
        if (len(splits) != 2) or (splits[0].lower() != "negotiate"):
            continue
        else:
            break
    else:
        print "No www-authenticate header with negotiate in second HTTP response."
        return        

    try:
        kerberos.authGSSClientStep(vc, splits[1])
    except kerberos.GSSError, e:
        print "Could not verify server www-authenticate header in second HTTP response: %s/%s" % (e[0][0], e[1][0])
        return
    
    try:
        rc = kerberos.authGSSClientClean(vc);
    except kerberos.GSSError, e:
        print "Could not clean-up GSSAPI: %s/%s" % (e[0][0], e[1][0])
        return

    print "Authenticated successfully"
    return

if __name__=='__main__':
    main()
