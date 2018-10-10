import kerberos
import os
import requests

username = os.environ.get('KERBEROS_USERNAME', 'administrator')
password = os.environ.get('KERBEROS_PASSWORD', 'Password01')
realm = os.environ.get('KERBEROS_REALM', 'example.com')
hostname = os.environ.get('KERBEROS_HOSTNAME', 'hostname.example.com')
port = os.environ.get('KERBEROS_PORT', '80')


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


def test_leaks_server():
    import gc

    SERVICE = "HTTP@%s" % hostname
    COUNT = 10

    def server_init():
        kerberos.authGSSServerInit(SERVICE)


    for _ in xrange(COUNT):
        server_init()
    # Because I'm not entirely certain that python's gc guaranty's timeliness
    # of destructors, lets kick off a manual gc.
    gc.collect()

    dirname = os.path.join('/proc/', str(os.getpid()), 'fd')
    for fname in  os.listdir(dirname):
        try:
            target = os.readlink(os.path.join(dirname, fname))
            print("fd {} => {}".format(fname, target))
        except EnvironmentError:
            pass
    # raw_input("Hit [ENTER] to continue> ")


def test_leaks_client():
    import gc
    import psutil

    SERVICE = "HTTP@%s" % hostname

    def client_init():
        kerberos.authGSSClientInit(SERVICE)


    def n_times(count):
        before = psutil.Process().memory_info().rss
        for _ in xrange(count):
            client_init()
        # Because I'm not entirely certain that python's gc guaranty's timeliness
        # of destructors, lets kick off a manual gc.
        gc.collect()
        after = psutil.Process().memory_info().rss
        delta = after - before
        print("Leaked {} total in {} calls: ~{} bytes per call".format(delta, count, delta / count))


    n_times(1000)
    n_times(10000)
    n_times(100000)
    n_times(1000000)

