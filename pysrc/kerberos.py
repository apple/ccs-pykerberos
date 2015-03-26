##
# Copyright (c) 2006-2015 Apple Inc. All rights reserved.
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
##

"""
PyKerberos Function Description.
"""



class KrbError(Exception):
    pass



class BasicAuthError(KrbError):
    pass



class GSSError(KrbError):
    pass



def checkPassword(user, pswd, service, default_realm):
    """
    This function provides a simple way to verify that a user name and password
    match those normally used for Kerberos authentication.
    It does this by checking that the supplied user name and password can be
    used to get a ticket for the supplied service.
    If the user name does not contain a realm, then the default realm supplied
    is used.

    For this to work properly the Kerberos must be configured properly on this
    machine.
    That will likely mean ensuring that the edu.mit.Kerberos preference file
    has the correct realms and KDCs listed.

    IMPORTANT: This method is vulnerable to KDC spoofing attacks and it should
    only used for testing. Do not use this in any production system - your
    security could be compromised if you do.

    @param user: A string containing the Kerberos user name.
        A realm may be included by appending an C{"@"} followed by the realm
        string to the actual user id.
        If no realm is supplied, then the realm set in the default_realm
        argument will be used.

    @param pswd: A string containing the password for the user.

    @param service: A string containing the Kerberos service to check access
        for.
        This will be of the form C{"sss/xx.yy.zz"}, where C{"sss"} is the
        service identifier (e.g., C{"http"}, C{"krbtgt"}), and C{"xx.yy.zz"} is
        the hostname of the server.

    @param default_realm: A string containing the default realm to use if one
        is not supplied in the user argument.
        Note that Kerberos realms are normally all uppercase (e.g.,
        C{"EXAMPLE.COM"}).

    @return: True if authentication succeeds, false otherwise.
    """



def changePassword(user, oldpswd, newpswd):
    """
    This function allows to change the user password on the KDC.

    @param user: A string containing the Kerberos user name.
        A realm may be included by appending a C{"@"} followed by the realm
        string to the actual user id.
        If no realm is supplied, then the realm set in the default_realm
        argument will be used.

    @param oldpswd: A string containing the old (current) password for the
        user.

    @param newpswd: A string containing the new password for the user.

    @return: True if password changing succeeds, false otherwise.
    """



def getServerPrincipalDetails(service, hostname):
    """
    This function returns the service principal for the server given a service
    type and hostname.
    Details are looked up via the C{/etc/keytab} file.

    @param service: A string containing the Kerberos service type for the
        server.

    @param hostname: A string containing the hostname of the server.

    @return: A string containing the service principal.
    """



"""
GSSAPI Function Result Codes:

    -1 : Error
    0  : GSSAPI step continuation (only returned by 'Step' function)
    1  : GSSAPI step complete, or function return OK

"""

# Some useful result codes
AUTH_GSS_CONTINUE     = 0
AUTH_GSS_COMPLETE     = 1

# Some useful gss flags
GSS_C_DELEG_FLAG      = 1
GSS_C_MUTUAL_FLAG     = 2
GSS_C_REPLAY_FLAG     = 4
GSS_C_SEQUENCE_FLAG   = 8
GSS_C_CONF_FLAG       = 16
GSS_C_INTEG_FLAG      = 32
GSS_C_ANON_FLAG       = 64
GSS_C_PROT_READY_FLAG = 128
GSS_C_TRANS_FLAG      = 256



def authGSSClientInit(service, **kwargs):
    """
    Initializes a context for GSSAPI client-side authentication with the given
    service principal.
    L{authGSSClientClean} must be called after this function returns an OK
    result to dispose of the context once all GSSAPI operations are complete.

    @param service: A string containing the service principal in the form
        C{"type@fqdn"}.

    @param principal: Optional string containing the client principal in the
        form C{"user@realm"}.

    @param gssflags: Optional integer used to set GSS flags.
        (e.g. C{GSS_C_DELEG_FLAG|GSS_C_MUTUAL_FLAG|GSS_C_SEQUENCE_FLAG} will
        allow for forwarding credentials to the remote host)

    @param delegated: Optional server context containing delegated credentials

    @return: A tuple of (result, context) where result is the result code (see
        above) and context is an opaque value that will need to be passed to
        subsequent functions.
    """



def authGSSClientClean(context):
    """
    Destroys the context for GSSAPI client-side authentication. After this call
    the context object is invalid and should not be used again.

    @param context: The context object returned from L{authGSSClientInit}.

    @return: A result code (see above).
    """



def authGSSClientStep(context, challenge):
    """
    Processes a single GSSAPI client-side step using the supplied server data.

    @param context: The context object returned from L{authGSSClientInit}.

    @param challenge: A string containing the base64-encoded server data (which
        may be empty for the first step).

    @return: A result code (see above).
    """



def authGSSClientResponse(context):
    """
    Get the client response from the last successful GSSAPI client-side step.

    @param context: The context object returned from L{authGSSClientInit}.

    @return: A string containing the base64-encoded client data to be sent to
        the server.
    """



def authGSSClientResponseConf(context):
    """
    Determine whether confidentiality was enabled in the previously unwrapped
    buffer.

    @param context: The context object returned from L{authGSSClientInit}.

    @return: C{1} if confidentiality was enabled in the previously unwrapped
        buffer, C{0} otherwise.
    """



def authGSSClientUserName(context):
    """
    Get the user name of the principal authenticated via the now complete
    GSSAPI client-side operations.
    This method must only be called after authGSSClientStep returns a complete
    response code.

    @param context: The context object returned from L{authGSSClientInit}.

    @return: A string containing the user name.
    """



def authGSSClientUnwrap(context, challenge):
    """
    Perform the client side GSSAPI unwrap step.

    @param challenge: A string containing the base64-encoded server data.

    @return: A result code (see above)
    """



def authGSSClientWrap(context, data, user=None, protect=0):
    """
    Perform the client side GSSAPI wrap step.

    @param data: The result of the L{authGSSClientResponse} after the
        L{authGSSClientUnwrap}.

    @param user: The user to authorize.

    @param protect: If C{0}, then just provide integrity protection.
        If C{1}, then provide confidentiality as well.

    @return: A result code (see above)
    """



def authGSSServerInit(service):
    """
    Initializes a context for GSSAPI server-side authentication with the given
    service principal.
    authGSSServerClean must be called after this function returns an OK result
    to dispose of the context once all GSSAPI operations are complete.

    @param service: A string containing the service principal in the form
        C{"type@fqdn"}.

    @return: A tuple of (result, context) where result is the result code (see
        above) and context is an opaque value that will need to be passed to
        subsequent functions.
    """



def authGSSServerClean(context):
    """
    Destroys the context for GSSAPI server-side authentication.
    After this call the context object is invalid and should not be used again.

    @param context: The context object returned from L{authGSSClientInit}.

    @return: A result code (see above).
    """



def authGSSServerStep(context, challenge):
    """
    Processes a single GSSAPI server-side step using the supplied client data.

    @param context: The context object returned from L{authGSSClientInit}.

    @param challenge: A string containing the base64-encoded client data.

    @return: A result code (see above).
    """



def authGSSServerResponse(context):
    """
    Get the server response from the last successful GSSAPI server-side step.

    @param context: The context object returned from L{authGSSClientInit}.

    @return: A string containing the base64-encoded server data to be sent to
        the client.
    """



def authGSSServerHasDelegated(context):
    """
    Checks whether a server context has delegated credentials.

    @param context: The context object returned from L{authGSSClientInit}.

    @return: A bool saying whether delegated credentials are available.
    """



def authGSSServerUserName(context):
    """
    Get the user name of the principal trying to authenticate to the server.
    This method must only be called after L{authGSSServerStep} returns a
    complete or continue response code.

    @param context: The context object returned from L{authGSSClientInit}.

    @return: A string containing the user name.
    """



def authGSSServerTargetName(context):
    """
    Get the target name if the server did not supply its own credentials.
    This method must only be called after L{authGSSServerStep} returns a
    complete or continue response code.

    @param context: The context object returned from L{authGSSClientInit}.

    @return: A string containing the target name.
    """



def authGSSServerStoreDelegate(context):
    """
    Save the ticket sent to the server in the file C{/tmp/krb5_pyserv_XXXXXX}.
    This method must only be called after L{authGSSServerStep} returns a
    complete or continue response code.

    @param context: The context object returned from L{authGSSClientInit}.

    @return: A result code (see above).
    """



def authGSSServerCacheName(context):
    """
    Get the name of the credential cache created with
    L{authGSSServerStoreDelegate}.
    This method must only be called after L{authGSSServerStoreDelegate}.

    @param context: The context object returned from L{authGSSClientInit}.

    @return: A string containing the cache name.
    """
