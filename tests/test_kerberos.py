import kerberos
import os
import socket
import ssl

try:
    from http.client import HTTPSConnection, HTTPConnection
except ImportError:
    from httplib import HTTPSConnection, HTTPConnection


username = os.environ['KERBEROS_USERNAME']
password = os.environ['KERBEROS_PASSWORD']
realm = os.environ['KERBEROS_REALM']
host = os.environ['KERBEROS_HOST']
port = os.environ['KERBEROS_PORT']
mech = "krb5"

host_fqdn = "%s.%s" % (host, realm.lower())


def test_service_principal():
    kerberos.getServerPrincipalDetails("HTTP", host_fqdn)


def test_basic_check_password():
    service = "HTTP/%s" % host_fqdn
    kerberos.checkPassword(username, password, service, realm)


def test_gssapi():
    """
    Return Code Values
        0 = Continue
        1 = Complete
        Other = Error
    """
    service = "HTTP@%s" % host_fqdn
    rc, vc = kerberos.authGSSClientInit(service)
    assert rc == 1, "authGSSClientInit = %d, expecting 1" % rc

    rs, vs = kerberos.authGSSServerInit(service)
    assert rs == 1, "authGSSServerInit = %d, expecting 1" % rs

    rc = kerberos.authGSSClientStep(vc, "")
    assert rc == 0, "authGSSClientStep = %d, expecting 0" % rc

    rs = kerberos.authGSSServerStep(vs, kerberos.authGSSClientResponse(vc))
    assert rs != -1, "authGSSServerStep = %d, not expecting it to be -1" % rs

    rc = kerberos.authGSSClientStep(vc, kerberos.authGSSServerResponse(vs))
    assert rc != -1, "authGSSClientStep = %d, not expecting it to be -1" % rc

    # TODO set assertions for this
    server_user_name = kerberos.authGSSServerUserName(vs)
    server_target_name = kerberos.authGSSServerTargetName(vs)
    client_user_name = kerberos.authGSSClientUserName(vc)

    rc = kerberos.authGSSClientClean(vc)
    assert rc == 1, "authGSSClientClean = %d, expecting it to be 0" % rc

    rs = kerberos.authGSSServerClean(vs)
    assert rs == 1, "authGSSServerClean = %d, expecting it to be 0" % rs


def test_http_endpoint():

    class HTTPSConnectionSSLv3(HTTPSConnection):
        "This class allows communication via SSL."

        def connect(self):
            "Connect to a host on a given (SSL) port."

            sock = socket.create_connection(
                (self.host, self.port), self.timeout
            )
            self.sock = ssl.wrap_socket(
                sock, self.key_file, self.cert_file,
                ssl_version=ssl.PROTOCOL_SSLv3
            )

    def sendRequest(host, port, use_ssl, method, uri, headers):
        response = None
        if use_ssl:
            http = HTTPSConnectionSSLv3(host, port)
        else:
            http = HTTPConnection(host, port)
        try:
            http.request(method, uri, "", headers)
            response = http.getresponse()
        finally:
            http.close()

        return response

    # Initial request without auth header
    service = "HTTP@%s" % host_fqdn
    uri = "/"
    response = sendRequest(host_fqdn, port, False, "OPTIONS", uri, {})

    if response is None:
        print("Initial HTTP request to server failed")
        return

    if response.status != 401:
        print("Initial HTTP request did not result in a 401 response")
        return

    try:
        # Python 2
        hdrs = response.msg.getheaders('www-authenticate')
    except AttributeError:
        # Python 3
        hdrs = [response.headers['www-authenticate']]

    if (hdrs is None) or (len(hdrs) == 0):
        print("No www-authenticate header in initial HTTP response.")
    for hdr in hdrs:
        hdr = hdr.strip()
        splits = hdr.split(' ', 1)
        if (len(splits) != 1) or (splits[0].lower() != "negotiate"):
            continue
        else:
            break
    else:
        print(
            "No www-authenticate header with negotiate in initial HTTP "
            "response."
        )
        return

    try:
        mech_oid = None
        if mech and mech.lower() == "krb5":
            mech_oid = kerberos.GSS_MECH_OID_KRB5
        elif mech and mech.lower() == "spnego":
            mech_oid = kerberos.GSS_MECH_OID_SPNEGO

        rc, vc = kerberos.authGSSClientInit(service=service, mech_oid=mech_oid)
    except kerberos.GSSError as e:
        print("Could not initialize GSSAPI: %s/%s" % (e[0][0], e[1][0]))
        return

    try:
        kerberos.authGSSClientStep(vc, "")
    except kerberos.GSSError as e:
        print(
            "Could not do GSSAPI step with continue: %s/%s"
            % (e[0][0], e[1][0])
        )
        return

    hdrs = {}
    hdrs["Authorization"] = "negotiate %s" % kerberos.authGSSClientResponse(vc)

    # Second request with auth header
    response = sendRequest(host_fqdn, port, False, "OPTIONS", uri, hdrs)

    if response is None:
        print("Second HTTP request to server failed")
        return

    if response.status / 100 != 2:
        print(
            "Second HTTP request did not result in a 2xx response: %d"
            % (response.status,)
        )
        return

    try:
        # Python 2
        hdrs = response.msg.getheaders('www-authenticate')
    except AttributeError:
        # Python 3
        hdrs = [response.headers['www-authenticate']]

    if (hdrs is None) or (len(hdrs) == 0):
        print("No www-authenticate header in second HTTP response.")
        return
    for hdr in hdrs:
        hdr = hdr.strip()
        splits = hdr.split(' ', 1)
        if (len(splits) != 2) or (splits[0].lower() != "negotiate"):
            continue
        else:
            break
    else:
        print(
            "No www-authenticate header with negotiate in second HTTP "
            "response."
        )
        return

    try:
        kerberos.authGSSClientStep(vc, splits[1])
    except kerberos.GSSError as e:
        print(
            "Could not verify server www-authenticate header in second HTTP "
            "response: %s/%s"
            % (e[0][0], e[1][0])
        )
        return

    try:
        kerberos.authGSSClientClean(vc)
    except kerberos.GSSError as e:
        print("Could not clean-up GSSAPI: %s/%s" % (e[0][0], e[1][0]))
        return

    print("Authenticated successfully")
    return
