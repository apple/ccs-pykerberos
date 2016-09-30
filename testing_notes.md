##### To test against a generic web service (and not CalendarServer)
... adjust test.py as shown below. uri should be something configured for kerberos authentication.


```
Index: test.py
===================================================================
--- test.py (revision 15646)
+++ test.py (working copy)
@@ -209,6 +209,7 @@
         else:
             http = HTTPConnection(host, port)
         try:
+            print("requesting: method: {}, uri: {}, body: '', headers: {}".format(method, uri, headers))
             http.request(method, uri, "", headers)
             response = http.getresponse()
         finally:
@@ -217,7 +218,7 @@
         return response
 
     # Initial request without auth header
-    uri = "/principals/"
+    uri = "http://server.example.org/test"
     response = sendRequest(host, port, use_ssl, "OPTIONS", uri, {})
 
     if response is None:
```

##### Sample Apache config for a kerberized location:
```
<Location /test>
         AuthType Kerberos
         AuthName "Kerberos:)"
         KrbMethodNegotiate on
         KrbMethodK5Passwd off
         Krb5Keytab /etc/apache2/http.keytab
         Require user userfoo@EXAMPLE.ORG
</Location>
```

##### the test.py help text
```
sudo ./test.py -s HTTP@example.com service
sudo ./test.py -u user01 -p user01 -s HTTP@example.com -r EXAMPLE.COM basic
sudo ./test.py -s HTTP@example.com -r EXAMPLE.COM gssapi
./test.py -s HTTP@example.com -h calendar.example.com -i 8008 server
For the gssapi and server tests you will need to kinit a principal on the server first.
```


##### basic test; performs an authentication with specified username / password (requires no credentials cache)
```
userfoo@domain-controller:~/PyKerberos$ python ./test.py -u userfoo -p myBestPassword -s HTTP@server.example.org -r EXAMPLE.ORG basic

*** Running basic test
Kerberos authentication for userfoo succeeded

*** Done
```

##### service test
Does what a kerberized service needs to do.
It wants to read the service keytab from /etc/krb5.keytab.
The ktutil steps shown here validate that the keytab is legit.
```
userfoo@domain-controller:~/PyKerberos$ sudo ktutil
ktutil:  rkt /etc/krb5.keytab
ktutil:  l
slot KVNO Principal
---- ---- ---------------------------------------------------------------------
   1    2    HTTP/server.example.org@EXAMPLE.ORG
   2    2    HTTP/server.example.org@EXAMPLE.ORG
   3    2    HTTP/server.example.org@EXAMPLE.ORG
   4    2    HTTP/server.example.org@EXAMPLE.ORG
ktutil:
userfoo@domain-controller:~/PyKerberos$ 
userfoo@domain-controller:~/PyKerberos$ sudo python ./test.py -s HTTP@server.example.org service

*** Running Service Principal test
Kerberos service principal for HTTP/server.example.org succeeded: HTTP/server.example.org@EXAMPLE.ORG

*** Done
```

##### gssapi test
requires user tgt and service keytab access (hence root), obtains service ticket for specified user / kerberized service
```
userfoo@domain-controller:~/PyKerberos$ sudo kinit userfoo
Password for userfoo@EXAMPLE.ORG: 
userfoo@domain-controller:~/PyKerberos$ sudo klist
Ticket cache: FILE:/tmp/krb5cc_0
Default principal: userfoo@EXAMPLE.ORG

Valid starting     Expires            Service principal
06/03/16 05:08:53  06/03/16 15:08:53  krbtgt/EXAMPLE.ORG@EXAMPLE.ORG
    renew until 06/04/16 05:08:52
userfoo@domain-controller:~/PyKerberos$ sudo python ./test.py -s HTTP@server.example.org -r EXAMPLE.ORG gssapi

*** Running GSSAPI test
Status for authGSSClientInit = Complete
Status for authGSSServerInit = Complete
Status for authGSSClientStep = Continue
Status for authGSSServerStep = Complete
Status for authGSSClientStep = Complete
Server user name: userfoo@EXAMPLE.ORG
Server target name: None
Client user name: userfoo@EXAMPLE.ORG
Status for authGSSClientClean = Complete
Status for authGSSServerClean = Complete

*** Done

userfoo@domain-controller:~/PyKerberos$ sudo klist
Ticket cache: FILE:/tmp/krb5cc_0
Default principal: userfoo@EXAMPLE.ORG

Valid starting     Expires            Service principal
06/03/16 05:08:53  06/03/16 15:08:53  krbtgt/EXAMPLE.ORG@EXAMPLE.ORG
    renew until 06/04/16 05:08:52
06/03/16 05:08:59  06/03/16 15:08:53  HTTP/server.example.org@EXAMPLE.ORG
    renew until 06/04/16 05:08:52
```

##### server test
connects to external kerberized service
```
userfoo@domain-controller:~/PyKerberos$ kdestroy
userfoo@domain-controller:~/PyKerberos$ python ./test.py -s HTTP@server.example.org -h domain-controller -i 80 server

*** Running HTTP test
requesting: method: OPTIONS, uri: http://server.example.org/test, body: '', headers: {}
Could not do GSSAPI step with continue: Unspecified GSS failure.  Minor code may provide more information/Credentials cache file '/tmp/krb5cc_1001' not found

*** Done

userfoo@domain-controller:~/PyKerberos$ klist
klist: No credentials cache found (ticket cache FILE:/tmp/krb5cc_1001)
userfoo@domain-controller:~/PyKerberos$ kinit
Password for userfoo@EXAMPLE.ORG: 
userfoo@domain-controller:~/PyKerberos$ klist
Ticket cache: FILE:/tmp/krb5cc_1001
Default principal: userfoo@EXAMPLE.ORG

Valid starting     Expires            Service principal
06/03/16 04:54:28  06/03/16 14:54:28  krbtgt/EXAMPLE.ORG@EXAMPLE.ORG
    renew until 06/04/16 04:54:27
userfoo@domain-controller:~/PyKerberos$ python ./test.py -s HTTP@server.example.org -h domain-controller -i 80 server

*** Running HTTP test
requesting: method: OPTIONS, uri: http://server.example.org/test, body: '', headers: {}
requesting: method: OPTIONS, uri: http://server.example.org/test, body: '', headers: {'Authorization': 'negotiate YIICbwYJKoZIhvcSAQICAQBuggJeMIICWqADAgEFoQMCAQ6iBwMFACAAAACjggFxYYIBbTCCAWmgAwIBBaEOGwxDTUlTU1lOQy5PUkeiJjAkoAMCAQOhHTAbGwRIVFRQGxNzZXJ2ZXIuY21pc3N5bmMub3Jno4IBKDCCASSgAwIBEqEDAgECooIBFgSCARJCT7c9mK+pKskUYbyUjQx1pGaQmrhbqjKoCgdMLEacnHvEANEH1vEzejiuEGPw/f96kKvMccaijEq8CzMm8nMicb1IJ8xYbZWHCSvIT8ccDRKlA5qf3vcQr002JSroKFuIFwivWGOIefg1cvsdNQ/jJ1Qf2pxLC2nxP6VFZdrtMwHI59rws1dUSNJ402cCjKV4OMLuWIrh0ivg7Lz7F1nCLFncSOYwJnDhoXUVh+paNl8Hc5RAv3LKLTab4dCpS3a1MK6o4LP4AlTne0O3caxInLCoQy3TOCRcIF9Jvug6XCEmbrZEfOfxz7fR/PSDseJOv3epI9hXgYoe0D0BdNRwOTMqhTUW40vnIiipwilPLduspIHPMIHMoAMCARKigcQEgcG5icdMbLukpIHSYDyrt/bVj/qKvfO8y4kQehZZ3CasPFNZwO/KDx1rOTSG7opo5bdhBBZAK4Z1YMIQUDSMHQ01uofBioJMdYGSTAwMCPM+yXYX5weaQd03SsxAUoCtdh9HuV25dbkkUskllqO2vlTiiAx9b/5BwUvKPAT6UXEvvRwXIvs8Aon5w3sYF0lrWGTPrWXvj1YCkddM6TeMb81ybhSmuh3AnUYIlAlJx4kwiY7wBBkVszXZCBfuYznmmLNH'}
Authenticated successfully

*** Done
```

##### appendix a: curl cross-check
Use curl to cross-check the kerberized http service
```
userfoo@domain-controller:~/PyKerberos$ kdestroy  
userfoo@domain-controller:~/PyKerberos$ curl --negotiate -u userfoo server.example.org/test
Enter host password for user 'userfoo':
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>401 Authorization Required</title>
</head><body>
<h1>Authorization Required</h1>
<p>This server could not verify that you
are authorized to access the document
requested.  Either you supplied the wrong
credentials (e.g., bad password), or your
browser doesn't understand how to supply
the credentials required.</p>
<hr>
<address>Apache/2.2.16 (Debian) Server at server.example.org Port 80</address>
</body></html>
userfoo@domain-controller:~/PyKerberos$ klist
klist: No credentials cache found (ticket cache FILE:/tmp/krb5cc_1001)
userfoo@domain-controller:~/PyKerberos$ kinit
Password for userfoo@EXAMPLE.ORG: 
userfoo@domain-controller:~/PyKerberos$ klist
Ticket cache: FILE:/tmp/krb5cc_1001
Default principal: userfoo@EXAMPLE.ORG

Valid starting     Expires            Service principal
06/03/16 03:12:43  06/03/16 13:12:43  krbtgt/EXAMPLE.ORG@EXAMPLE.ORG
    renew until 06/04/16 03:12:42
userfoo@domain-controller:~/PyKerberos$ curl --negotiate -u userfoo server.example.org/test
Enter host password for user 'userfoo':
it works! :)
userfoo@domain-controller:~/PyKerberos$ klist
Ticket cache: FILE:/tmp/krb5cc_1001
Default principal: userfoo@EXAMPLE.ORG

Valid starting     Expires            Service principal
06/03/16 03:12:43  06/03/16 13:12:43  krbtgt/EXAMPLE.ORG@EXAMPLE.ORG
    renew until 06/04/16 03:12:42
06/03/16 03:12:49  06/03/16 13:12:43  HTTP/server.example.org@EXAMPLE.ORG
    renew until 06/04/16 03:12:42
```

##### appendix b: calling httplib
hold httplib in your hands to help discover that you were passing the wrong cli option to test.py for 'port', causing it to try to connect to 8008, which was refused!
```
>>> import httplib
>>> http = httplib.HTTPConnection('domain-controller', 80)
>>> http
<httplib.HTTPConnection instance at 0x7f9ed9c680e0>
>>> 
>>> http.request("GET", "http://domain-controller", "", {})
>>> response = http.getresponse()
>>> response
<httplib.HTTPResponse instance at 0x7f9ed9c68638>
>>> response.status
200

>>> import httplib
>>> http = httplib.HTTPConnection('domain-controller', 80)
>>> http.request("GET", "http://domain-controller/test", "", {})
>>> response = http.getresponse()
>>> response.status
401
```
