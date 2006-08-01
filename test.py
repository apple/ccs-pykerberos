##
# Copyright (c) 2006 Apple Computer, Inc. All rights reserved.
#
# This file contains Original Code and/or Modifications of Original Code
# as defined in and that are subject to the Apple Public Source License
# Version 2.0 (the 'License'). You may not use this file except in
# compliance with the License. Please obtain a copy of the License at
# http://www.opensource.apple.com/apsl/ and read it before using this
# file.
# 
# The Original Code and all software distributed under the License are
# distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
# EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
# INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
# Please see the License for the specific language governing rights and
# limitations under the License.
#
# DRI: Cyrus Daboo, cdaboo@apple.com
##

import kerberos
import getopt
import sys
import httplib

def main():
    
    # Extract arguments
    user = ""
    pswd = ""
    service = "http@caldav.apple.com"
    host = "localhost"
    port = 8008
    ssl = False
    
    options, args = getopt.getopt(sys.argv[1:], "u:p:s:h:i:")

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
    
    # Run tests
    if (len(user) != 0) and (len(pswd) != 0):
        print "\n*** Running basic test"
        testCheckpassword(user, pswd)
    else:
        print "\n*** Skipping basic test: no user or password specified"

    print "\n*** Running GSSAPI test"
    #testGSSAPI(service)

    print "\n*** Running HTTP test"
    testHTTP(host, port, ssl, service)

    print "\n*** Done\n"

def testCheckpassword(user, pswd):
    result = kerberos.checkPassword(user, pswd, "http/web.apple.com", "APPLECONNECT.APPLE.COM")
    if result:
        print "Kerberos authentication for %s succeeded" % user
    else:
        print "Kerberos authentication for %s failed" % user

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
    print "Client user name: %s" % kerberos.authGSSClientUserName(vc);
    
    rc = kerberos.authGSSClientClean(vc);
    print "Status for authGSSClientClean = %s" % statusText(rc);
    
    rs = kerberos.authGSSServerClean(vs);
    print "Status for authGSSServerClean = %s" % statusText(rs);

def testHTTP(host, port, ssl, service):
    def sendRequest(host, port, ssl, method, uri, headers):
        response = None
        if ssl:
            http = httplib.HTTPSConnection(host, port)
        else:
            http = httplib.HTTPConnection(host, port)
        try:
            http.request(method, uri, "", headers)
            response = http.getresponse()
        finally:
            http.close()
        
        return response

    # Initial request without auth header
    response = sendRequest(host, port, ssl, "OPTIONS", "/", {})
    
    if response is None:
        print "Initial HTTP request to server failed"
        return
    
    if response.status != 401:
        print "Initial HTTP request did not result in a 404 response"
        return
    
    hdrs = response.msg.getheaders("www-authenticate")
    if (hdrs is None) or (len(hdrs) == 0):
        print "No www-authenticate header in initial HTTP response."
    if len(hdrs) != 1:
        print "Too many www-authenticate headers in initial HTTP response."
        return
    hdr = hdrs[0].strip()
    splits = hdr.split(' ', 1)
    if (len(splits) != 1) or (splits[0].lower() != "negotiate"):
        print "Incorrect www-authenticate header in initial HTTP response: %s" % hdr        
        return

    rc, vc = kerberos.authGSSClientInit(service);
    if rc != 1:
        print "Could not initialize GSSAPI"
        return

    rc = kerberos.authGSSClientStep(vc, "");
    if rc != 0:
        print "Could not do GSSAPI setp with continue"
        return

    hdrs = {}
    hdrs["Authorization"] = "negotiate %s" % kerberos.authGSSClientResponse(vc)    

    # Second request with auth header
    response = sendRequest(host, port, ssl, "OPTIONS", "/", hdrs)
    
    if response is None:
        print "Second HTTP request to server failed"
        return
    
    if response.status/100 != 2:
        print "Second HTTP request did not result in a 2xx response"
        return
    
    hdrs = response.msg.getheaders("www-authenticate")
    if (hdrs is None) or (len(hdrs) == 0):
        print "No www-authenticate header in second HTTP response."
        return
    if len(hdrs) != 1:
        print "Too many www-authenticate headers in second HTTP response."
        return
    hdr = hdrs[0].strip()
    splits = hdr.split(' ', 1)
    if (len(splits) != 2) or (splits[0].lower() != "negotiate"):
        print "Incorrect www-authenticate header in second HTTP response: %s" % hdr        
        return
    
    rc = kerberos.authGSSClientStep(vc, splits[1]);
    if rc != 1:
        print "Could not verify server www-authenticate header in second HTTP response"
        return
    
    rc = kerberos.authGSSClientClean(vc);
    if rc != 1:
        print "Could not clean-up GSSAPI"
        return

    return

if __name__=='__main__':
    main()
