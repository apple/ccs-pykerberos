import kerberos
import os
import requests

username = os.environ['KERBEROS_USERNAME']
password = os.environ['KERBEROS_PASSWORD']
realm = os.environ['KERBEROS_REALM']
hostname = os.environ['KERBEROS_HOSTNAME']
port = os.environ['KERBEROS_PORT']


def test_service_principal():
    expected = "HTTP/%s@%s" % (hostname, realm.upper())
    actual = kerberos.getServerPrincipalDetails("HTTP", hostname)

    assert actual == expected, "The returned SPN does not match with test expectations"


def test_basic_check_password():
    service = "HTTP/%s" % hostname
    actual = kerberos.checkPassword(username, password, service, realm.upper())

    assert actual, "Checking of the password failed"


def test_gssapi():
    """
    Return Code Values
        0 = Continue
        1 = Complete
        Other = Error
    """
    service = "HTTP@%s" % hostname
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

    expected_username = "%s@%s" % (username, realm.upper())
    server_user_name = kerberos.authGSSServerUserName(vs)
    assert server_user_name == expected_username, "Invalid server username returned"

    client_user_name = kerberos.authGSSClientUserName(vc)
    assert client_user_name == expected_username, "Invalid client username returned"

    server_target_name = kerberos.authGSSServerTargetName(vs)
    assert server_target_name is None, "Server target name is not None"

    rc = kerberos.authGSSClientClean(vc)
    assert rc == 1, "authGSSClientClean = %d, expecting it to be 0" % rc

    rs = kerberos.authGSSServerClean(vs)
    assert rs == 1, "authGSSServerClean = %d, expecting it to be 0" % rs


def test_http_endpoint():
    service = "HTTP@%s" % hostname
    url = "http://%s:%s/" % (hostname, port)

    session = requests.Session()

    # Send the initial request un-authenticated
    request = requests.Request('GET', url)
    prepared_request = session.prepare_request(request)
    response = session.send(prepared_request)

    # Expect a 401 response
    assert response.status_code == 401, "Initial HTTP request did not result in a 401 response"

    # Validate the response supports the Negotiate protocol
    header = response.headers.get('www-authenticate', None)
    assert header is not None, "Initial HTTP response did not contain the www-authenticate header"
    assert header == 'Negotiate', "Initial HTTP response header www-authenticate does not support Negotiate"

    # Generate the first Kerberos token
    mech_oid = kerberos.GSS_MECH_OID_KRB5
    rc, vc = kerberos.authGSSClientInit(service=service, mech_oid=mech_oid)
    kerberos.authGSSClientStep(vc, "")
    kerberos_token = kerberos.authGSSClientResponse(vc)

    # Attach the Kerberos token and resend back to the host
    request = requests.Request('GET', url)
    prepared_request = session.prepare_request(request)
    prepared_request.headers['Authorization'] = "Negotiate %s" % kerberos_token
    response = session.send(prepared_request)

    # Expect a 200 response
    assert response.status_code == 200, "Second HTTP request did not result in a 200 response"

    # Validate the headers exist and contain a www-authenticate message
    header = response.headers.get('www-authenticate', None)
    assert header is not None, "Second HTTP response did not contain the www-authenticate header"
    assert header.startswith("Negotiate ")

    # Verify the return Kerberos token
    server_kerberos_token = header.split(' ')[-1]
    kerberos.authGSSClientStep(vc, server_kerberos_token)

    # Cleanup any objects still stored in memory
    kerberos.authGSSClientClean(vc)
