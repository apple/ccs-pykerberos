
#include "kerberosgss.h"

#include "stdio.h"

int main (int argc, char * const argv[]) {
	
	int code = 0;
	char* service = 0L;
	gss_server_state state;
	
	service = server_principal_details("http", "caldav.corp.apple.com");

	//printf("Got service principal: %s\n", result);
	
	//code = authenticate_user_krb5pwd("x", "x", "http/caldav.corp.apple.com@CALDAV.CORP.APPLE.COM", "CALDAV.CORP.APPLE.COM");

	code = authenticate_gss_server_init("http@CALDAV.CORP.APPLE.COM", &state);
	code = authenticate_gss_server_clean(&state);

    return 0;
}
