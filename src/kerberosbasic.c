/**
 * Copyright (c) 2006-2018 Apple Inc. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 **/

#include <Python.h>
#include "kerberosbasic.h"

#include <krb5/krb5.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>

#undef PRINTFS

extern PyObject *BasicAuthException_class;
static void set_basicauth_error(krb5_context context, krb5_error_code code);

static krb5_error_code verify_krb5_user(
    krb5_context context, krb5_principal principal, const char *password,
    krb5_principal server, int ticket_life, int renew_life
);

static int set_cc_env_var(const char *name, krb5_context context, krb5_ccache *out_cc);

int authenticate_user_krb5pwd(
    const char *user, const char *pswd, const char *service,
    const char *default_realm, int ticket_life, int renew_life
) {
    krb5_context    kcontext = NULL;
    krb5_error_code code;
    krb5_principal  client = NULL;
    krb5_principal  server = NULL;
    int             ret = 0;
    char            *name = NULL;
    char            *p = NULL;

    code = krb5_init_context(&kcontext);
    if (code)
    {
        PyErr_SetObject(
            BasicAuthException_class,
            Py_BuildValue(
                "((s:i))", "Cannot initialize Kerberos5 context", code
            )
        );
        return 0;
    }

    ret = krb5_parse_name (kcontext, service, &server);

    if (ret) {
        set_basicauth_error(kcontext, ret);
        ret = 0;
        goto end;
    }

    code = krb5_unparse_name(kcontext, server, &name);
    if (code) {
        set_basicauth_error(kcontext, code);
        ret = 0;
        goto end;
    }
#ifdef PRINTFS
    printf("Using %s as server principal for password verification\n", name);
#endif
    free(name);
    name = NULL;

    name = (char *)malloc(256);
    if (name == NULL)
    {
        PyErr_NoMemory();
        ret = 0;
        goto end;
    }
    p = strchr(user, '@');
    if (p == NULL) {
        snprintf(name, 256, "%s@%s", user, default_realm);
    } else {
        snprintf(name, 256, "%s", user);
    }

    code = krb5_parse_name(kcontext, name, &client);
    if (code) {
        set_basicauth_error(kcontext, code);
        ret = 0;
        goto end;
    }

    code = verify_krb5_user(kcontext, client, pswd, server, ticket_life, renew_life);

    if (code) {
        ret = 0;
        goto end;
    }

    ret = 1;

end:
#ifdef PRINTFS
    printf(
        "kerb_authenticate_user_krb5pwd ret=%d user=%s authtype=%s\n",
        ret, user, "Basic"
    );
#endif
    if (name) {
        free(name);
    }
    if (client) {
        krb5_free_principal(kcontext, client);
    }
    if (server) {
        krb5_free_principal(kcontext, server);
    }
    krb5_free_context(kcontext);

    return ret;
}

int renew_ticket_krb5(
    const char *user, const char *service, const char *default_realm
) {
    krb5_context    kcontext = NULL;
    krb5_error_code code;
    krb5_principal  client = NULL;
    krb5_principal  server = NULL;
    krb5_ccache     mcc = NULL;
    int             ret = 0;
    char            *name = NULL;
    char            *p = NULL;
    int             now = time(0);
    krb5_cc_cursor  cur;
    bool            valid_cred = false;

    code = krb5_init_context(&kcontext);
    if (code)
    {
        PyErr_SetObject(
            BasicAuthException_class,
            Py_BuildValue(
                "((s:i))", "Cannot initialize Kerberos5 context", code
            )
        );
        return 0;
    }

    ret = krb5_parse_name (kcontext, service, &server);

    if (ret) {
        set_basicauth_error(kcontext, ret);
        ret = 0;
        goto end;
    }

    code = krb5_unparse_name(kcontext, server, &name);
    if (code) {
        set_basicauth_error(kcontext, code);
        ret = 0;
        goto end;
    }
#ifdef PRINTFS
    printf("Using %s as server principal for password verification\n", name);
#endif
    free(name);
    name = NULL;

    name = (char *)malloc(256);
    if (name == NULL)
    {
        PyErr_NoMemory();
        ret = 0;
        goto end;
    }
    p = strchr(user, '@');
    if (p == NULL) {
        snprintf(name, 256, "%s@%s", user, default_realm);
    } else {
        snprintf(name, 256, "%s", user);
    }

    code = krb5_parse_name(kcontext, name, &client);
    if (code) {
        set_basicauth_error(kcontext, code);
        ret = 0;
        goto end;
    }

    krb5_ccache out_cc = NULL;
    set_cc_env_var(name, kcontext, &out_cc);

    if ((ret = krb5_cc_start_seq_get(kcontext, out_cc, &cur)) != 0) {
        set_basicauth_error(kcontext, ret);
        ret = 0;
        goto end;
    }

    krb5_creds old_creds;
    while ((ret = krb5_cc_next_cred(kcontext, out_cc, &cur, &old_creds)) == 0) {
        if(old_creds.times.endtime > now) {
            valid_cred = true;
            break;
        }
    }

    if((ret = krb5_cc_end_seq_get(kcontext, out_cc, &cur)) != 0) {
        set_basicauth_error(kcontext, ret);
        goto end;
    }

    krb5_creds new_creds;
    ret = krb5_get_renewed_creds(kcontext, &new_creds, client, out_cc, NULL);
    if (ret) {
        if(valid_cred) {
            ret = 1;
            goto end;
        }
        set_basicauth_error(kcontext, ret);
        ret = 0;
        goto end;
    }

    ret = krb5_cc_new_unique(kcontext, "MEMORY", NULL, &mcc);
    if (!ret)
        ret = krb5_cc_initialize(kcontext, mcc, client);
    if (ret) {
        set_basicauth_error(kcontext, ret);
        ret = 0;
        goto end;
    }

    // not ideal, in kinit they have a special function k5_cc_store_primary_cred, but that is not in include files,
    // so we're just using store_cred
    ret = krb5_cc_store_cred(kcontext, mcc, &new_creds);
    if (ret) {
        set_basicauth_error(kcontext, ret);
        ret = 0;
        goto end;
    }
    ret = krb5_cc_move(kcontext, mcc, out_cc);
    if (ret) {
        set_basicauth_error(kcontext, ret);
        ret = 0;
        goto end;
    }
    mcc = NULL;

    ret = 1;

end:
#ifdef PRINTFS
    printf(
        "kerb_authenticate_user_krb5pwd ret=%d user=%s authtype=%s\n",
        ret, user, "Basic"
    );
#endif
    if (name) {
        free(name);
    }
    if (client) {
        krb5_free_principal(kcontext, client);
    }
    if (server) {
        krb5_free_principal(kcontext, server);
    }
    krb5_free_context(kcontext);

    return ret;
}

/* Inspired by krb5_verify_user from Heimdal */
static krb5_error_code verify_krb5_user(
    krb5_context context, krb5_principal principal, const char *password,
    krb5_principal server, int ticket_life, int renew_life
) {
    krb5_creds creds;
    krb5_get_init_creds_opt *gic_options;
    krb5_error_code ret;
    char *name = NULL;
    krb5_ccache out_cc = NULL;

    memset(&creds, 0, sizeof(creds));

    ret = krb5_unparse_name(context, principal, &name);
    if (ret == 0) {
        ret = set_cc_env_var(name, context, &out_cc);
        if(ret) {
            set_basicauth_error(context, ret);
            goto end;
        }
        free(name);
    } else {
        set_basicauth_error(context, ret);
        goto end;
    }

    ret = krb5_get_init_creds_opt_alloc(context, &gic_options);
    if (ret) {
        set_basicauth_error(context, ret);
        goto end;
    }

    krb5_get_init_creds_opt_set_tkt_life(gic_options, ticket_life);
    krb5_get_init_creds_opt_set_renew_life(gic_options, renew_life);
    ret = krb5_get_init_creds_opt_set_out_ccache(context, gic_options, out_cc);
    if (ret) {
        set_basicauth_error(context, ret);
        goto end;
    }

    ret = krb5_get_init_creds_password(
        context, &creds, principal, (char *)password,
        NULL, NULL, 0, NULL, gic_options
    );
    if (ret) {
        set_basicauth_error(context, ret);
        goto end;
    }

    ret = krb5_verify_init_creds(context, &creds, server, NULL, NULL, NULL);
    /* If we couldn't verify credentials against keytab, return error */
    if (ret) {
        set_basicauth_error(context, ret);
        goto end;
    }

    ret = krb5_cc_switch(context, out_cc);
    if (ret) {
        set_basicauth_error(context, ret);
        goto end;
    }

end:
    krb5_free_cred_contents(context, &creds);

    return ret;
}

static void set_basicauth_error(krb5_context context, krb5_error_code code)
{
    PyErr_SetObject(
        BasicAuthException_class,
        Py_BuildValue("(s:i)", krb5_get_err_text(context, code), code)
    );
}

static int set_cc_env_var(const char *name, krb5_context context, krb5_ccache *out_cc) {
#ifdef PRINTFS
    printf("Trying to get TGT for user %s\n", name);
#endif

    char *filepath = malloc(1024);
    if(filepath == NULL) {
        return 1;
    }
    sprintf(filepath, "FILE:/tmp/krb5cc_%s", name);
    int ret = krb5_cc_resolve(context, filepath, out_cc);
    if (ret) {
        return ret;
    }
    setenv("KRB5CCNAME", filepath, 1);
    free(filepath);
    return 0;
}