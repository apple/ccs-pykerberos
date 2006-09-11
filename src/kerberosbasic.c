/**
 * Copyright (c) 2006 Apple Computer, Inc. All rights reserved.
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
 *
 * DRI: Cyrus Daboo, cdaboo@apple.com
 **/

#include "kerberosbasic.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#undef PRINTFS

static krb5_error_code verify_krb5_user(krb5_context context, krb5_principal principal, const char *password, krb5_principal server);

int authenticate_user_krb5pwd(const char *user, const char *pswd, const char *service, const char *default_realm)
{
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
#ifdef PRINTFS
		printf("Cannot initialize Kerberos5 context (%d)\n", code);
#endif
		return 0;
	}
	
	ret = krb5_parse_name (kcontext, service, &server);
	
	if (ret)
	{
#ifdef PRINTFS
		printf("Error parsing server name (%s): %s\n", service, krb5_get_err_text(kcontext, ret));
#endif
		ret = 0;
		goto end;
	}
	
	code = krb5_unparse_name(kcontext, server, &name);
	if (code)
	{
#ifdef PRINTFS
		printf("krb5_unparse_name() failed: %s\n", krb5_get_err_text(kcontext, code));
#endif
		ret = 0;
		goto end;
	}
#ifdef PRINTFS
	printf("Using %s as server principal for password verification\n", name);
#endif
	free(name);
	name = NULL;
	
	name = (char *)malloc(256);
	p = strchr(user, '@');
	if (p == NULL)
	{
		snprintf(name, 256, "%s@%s", user, default_realm);
	}
	else
	{
		snprintf(name, 256, "%s", user);
	}
		
	code = krb5_parse_name(kcontext, name, &client);
	if (code)
	{
#ifdef PRINTFS
		printf("krb5_parse_name() failed: %s\n", krb5_get_err_text(kcontext, code));
#endif
		ret = 0;
		goto end;
	}
		
	code = verify_krb5_user(kcontext, client, pswd, server);
	
	if (code)
	{
		ret = 0;
		goto end;
	}

	ret = 1;
	
end:
#ifdef PRINTFS
	printf("kerb_authenticate_user_krb5pwd ret=%d user=%s authtype=%s\n", ret, user, "Basic");
#endif
	if (name)
		free(name);
	if (client)
		krb5_free_principal(kcontext, client);
	if (server)
		krb5_free_principal(kcontext, server);
	krb5_free_context(kcontext);

	
	return ret;
}

/* Inspired by krb5_verify_user from Heimdal */
static krb5_error_code verify_krb5_user(krb5_context context, krb5_principal principal, const char *password, krb5_principal server)
{
	krb5_creds creds;
	krb5_error_code ret;
	char *name = NULL;
	
	memset(&creds, 0, sizeof(creds));
	
	ret = krb5_unparse_name(context, principal, &name);
	if (ret == 0)
	{
#ifdef PRINTFS
		printf("Trying to get TGT for user %s\n", name);
#endif
		free(name);
	}
	
	ret = krb5_get_init_creds_password(context, &creds, principal, (char *)password, NULL, NULL, 0, NULL, NULL);
	if (ret)
	{
#ifdef PRINTFS
		printf("krb5_get_init_creds_password() failed: %s\n",  krb5_get_err_text(context, ret));
#endif
		goto end;
	}
	
end:
	krb5_free_cred_contents(context, &creds);
	
	return ret;
}

