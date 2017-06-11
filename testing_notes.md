# Setting up a Test Environment

While you can just use the automated travis-ci build to test out your changes
it is also nice to be able to run the tests locally before pushing them.
Unfortunately due to the nature of Kerberos it can be hard to have an
environment on hand to test this out. Please note that any scripts or commands
run are not indicative of a properly secured and hardened Kerberos environment
and should not be used to set up a real Kerberos environment used in a non
testing context.

The script .travis.sh is the script used in the automated travis-ci build and
can be run locally. You can take parts of this script to install a Kerberos
KDC and Apache site secured with Kerberos and run the tests using py.test.
Otherwise you can run the tests on a host already connected to your own domain
and modify the values in `tests/test_kerberos.py` which is valid for your
environment. See an explanation for each option below;

```
# The username without the realm to validate
username = os.environ.get('KERBEROS_USERNAME', 'administrator')

# The password for the username
password = os.environ.get('KERBEROS_PASSWORD', 'Password01')

# The realm/domain of your environment in lowercase
realm = os.environ.get('KERBEROS_REALM', 'example.com')

# The FQDN of the host
hostname = os.environ.get('KERBEROS_HOSTNAME', 'hostname.example.com')

# The port the Apache site is listening to
port = os.environ.get('KERBEROS_PORT', '80')
```

## Sample Apache config for a Kerberized site

You can use the package [mod_auth_gssapi](https://github.com/modauthgssapi/mod_auth_gssapi) to secure your Apache site with
Kerberos authentication. For you to do this you can install the package by
running;

```bash
# for Debian/Ubuntu:
sudo apt-get install libapache2-mod-auth-gssapi

# for RHEL/CentOS:
sudo yum install mod_auth_gssapi
```

In your site configuration an example setup of the config would
look something like this

```
<VirtualHost *:80>
    ServerName hostname.example.com
    ServerAlias hostname.example.com
    DocumentRoot /var/www/example.com/public_html
    ErrorLog ${APACHE_LOG_DIR}/error.log
    CustomLog ${APACHE_LOG_DIR}/access.log combined
    <Directory "/var/www/example.com/public_html">
        AuthType GSSAPI
        AuthName "GSSAPI Single Sign On Login"
        Require user username@EXAMPLE.COM
        GssapiCredStore keytab:/etc/krb5.keytab
    </Directory>
</VirtualHost>
```

Your keytab file needs to have the SPN added for the site, this can be done by
running on your KDC

```bash
kadmin.local -q "addprinc -randkey HTTP/hostname.example.com"

kadmin.local -q "ktadd -k /etc/krb5.keytab HTTP/hostname.example.com"
```

Take note to change the hostname used with the actual hostname of your host.

# Test Cases

There are currently 4 test cases in this library

* basic
* service
* gssapi
* server

## Basic Test

This test performs a basic authentication test with the specified username /
password. This does not require any credentials to be cached.

## Service Test

Does what a Kerberized service needs to do. It attempts to read the service
keytab from `/etc/krb5.keytab`. Before running this test you need to ensure
`/etc/krb5.keytab` contains the keytab `HTTP/hostname.example.com@EXAMPLE.COM`
where the hostname and realm suite your environment. You can verify this by
running

```
[administrator@HOSTNAME ]$ klist -k /etc/krb5.keytab
Keytab name: FILE:/etc/krb5.keytab
KVNO Principal
---- --------------------------------------------------------------------------
   1 HTTP/hostname.example.com@EXAMPLE.COM
   2 host/hostname.example.com@EXAMPLE.COM
   2 host/hostname.example.com@EXAMPLE.COM
   2 host/hostname.example.com@EXAMPLE.COM
   2 host/hostname.example.com@EXAMPLE.COM
   2 host/hostname.example.com@EXAMPLE.COM
   2 host/HOSTNAME@EXAMPLE.COM
   2 host/HOSTNAME@EXAMPLE.COM
   2 host/HOSTNAME@EXAMPLE.COM
   2 host/HOSTNAME@EXAMPLE.COM
   2 host/HOSTNAME@EXAMPLE.COM
   2 HOSTNAME@EXAMPLE.COM
   2 HOSTNAME@EXAMPLE.COM
   2 HOSTNAME@EXAMPLE.COM
   2 HOSTNAME@EXAMPLE.COM
   2 HOSTNAME@EXAMPLE.COM
```

Your keytab can contain other entries it just needs to contain the one
mentioned above.

## GSSAPI Test

Requires user tgt and service keytab access (hence root), this test will
obtain the service ticker for the specified user

```
userfoo@domain-controller:~/PyKerberos$ sudo kinit userfoo
Password for userfoo@EXAMPLE.ORG:
userfoo@domain-controller:~/PyKerberos$ sudo klist
Ticket cache: FILE:/tmp/krb5cc_0
Default principal: userfoo@EXAMPLE.ORG

Valid starting     Expires            Service principal
06/03/16 05:08:53  06/03/16 15:08:53  krbtgt/EXAMPLE.ORG@EXAMPLE.ORG
    renew until 06/04/16 05:08:52
userfoo@domain-controller:~/PyKerberos$ sudo py.test

userfoo@domain-controller:~/PyKerberos$ sudo klist
Ticket cache: FILE:/tmp/krb5cc_0
Default principal: userfoo@EXAMPLE.ORG

Valid starting     Expires            Service principal
06/03/16 05:08:53  06/03/16 15:08:53  krbtgt/EXAMPLE.ORG@EXAMPLE.ORG
    renew until 06/04/16 05:08:52
06/03/16 05:08:59  06/03/16 15:08:53  HTTP/server.example.org@EXAMPLE.ORG
    renew until 06/04/16 05:08:52
```

## Server Test

This test will validate Kerberos authentication against a HTTP endpoint
protected by Kerberos authentication. It requires a HTTP website set up and
running, details on this can be found in the sections above and in the
`.travis-ci.sh` script.

## Appendix

### appendix a: curl cross-check
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

### appendix b: calling httplib
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
