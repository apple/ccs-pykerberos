/**
 * Copyright (c) 2006-2009 Apple Inc. All rights reserved.
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

#include "kerberosgss.h"

#include "stdio.h"

int main (int argc, char * const argv[]) {

	int code = 0;
	char* service = 0L;
	gss_server_state state;

	service = server_principal_details("http", "caldav.local");

	//printf("Got service principal: %s\n", result);

	//code = authenticate_user_krb5pwd("x", "x", "http/caldav.corp.apple.com@CALDAV.CORP.APPLE.COM", "CALDAV.CORP.APPLE.COM");

	code = authenticate_gss_server_init("", &state);
	code = authenticate_gss_server_clean(&state);

    return 0;
}
