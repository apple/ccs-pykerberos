import kerberos
import os
import pytest
import requests

from requests_kerberos import HTTPKerberosAuth

username = os.environ.get('KERBEROS_USERNAME', 'administrator')
password = os.environ.get('KERBEROS_PASSWORD', 'Password01')
service = os.environ.get('KERBEROS_SERVICE', 'HTTP@6824081c851a.example.com')
realm = os.environ.get('KERBEROS_REALM', 'EXAMPLE.COM')

def test_service_principal():
    kerberos.getServerPrincipalDetails("HTTP", "6824081c851a.example.com")

def test_basic_check_password():
    kerberos.checkPassword(username, password, service, realm)

def test_gssapi():
    """
    Return Code Values
        0 = Continue
        1 = Complete
        Other = Error
    """
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
    endpoint = "http://6824081c851a.example.com"
    session = requests.Session()
    session.auth = HTTPKerberosAuth()
    request = requests.Request('GET', endpoint)
    prepared_request = session.prepare_request(request)
    response = session.send(prepared_request)
    response.raise_for_status()
    assert response.text == "a"
