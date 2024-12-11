#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ppport.h"

#include "../check_auth_bystr.h"


/*
int check_auth_bystr(char* host, int port, char* user, char* pass, int chmode)
{
    int ret;
    Buffer hst, usr, pas;

    hst = make_Buffer_bystr(host);
    usr = make_Buffer_bystr(user);
    pas = make_Buffer_bystr(pass);
   
    ret = check_auth(hst, (int)port, usr, pas, chmode, SSL_DH, SSL_AES128CBC, NULL, TRUE);

    free_Buffer(&hst);
    free_Buffer(&usr);
    free_Buffer(&pas);

	return ret;
}
*/
   


MODULE = perl_jbxl_auth		PACKAGE = perl_jbxl_auth		


int
check_auth(hname, port, user, pass, chmode)
    char* hname
	int   port
    char* user
    char* pass
    int   chmode
CODE:
    RETVAL = check_auth_bystr(hname, port, user, pass, chmode);
OUTPUT:
    RETVAL


