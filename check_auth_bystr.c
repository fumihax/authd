
#include "isnet.h"

#include "check_auth_bystr.h"


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
   

