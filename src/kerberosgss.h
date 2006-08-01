/**
 * Copyright (c) 2006 Apple Computer, Inc. All rights reserved.
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * DRI: Cyrus Daboo, cdaboo@apple.com
 **/

#include <Kerberos/gssapi.h>
#include <Kerberos/gssapi_generic.h>
#include <Kerberos/gssapi_krb5.h>
#include <Kerberos/krb_err.h>

#define krb5_get_err_text(context,code) error_message(code)

#define AUTH_GSS_ERROR		-1
#define AUTH_GSS_COMPLETE	1
#define AUTH_GSS_CONTINUE	0

typedef struct {
	gss_ctx_id_t    context;
	gss_name_t		server_name;
	char*			username;
	char*			response;
} gss_client_state;

typedef struct {
	gss_ctx_id_t    context;
	gss_name_t		server_name;
	gss_name_t		client_name;
    gss_cred_id_t	server_creds;
    gss_cred_id_t	client_creds;
	char*			username;
	char*			response;
} gss_server_state;

int authenticate_gss_client_init(const char* service, gss_client_state *state);
int authenticate_gss_client_clean(gss_client_state *state);
int authenticate_gss_client_step(gss_client_state *state, const char *challenge);

int authenticate_gss_server_init(const char* service, gss_server_state *state);
int authenticate_gss_server_clean(gss_server_state *state);
int authenticate_gss_server_step(gss_server_state *state, const char *challenge);
