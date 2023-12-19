


#include "check_auth.h"



int main(int argc, char** argv)
{
    int    i, err, port, cryptmode, chlngmode;
    Buffer hostname, buf, svr, usr, pas;


    if (argc<7) {
        fprintf(stderr,"Usage... %s -h host_name[:port] -u userid -p passwd [-m] [-s] [-d]\n",argv[0]);
        exit(0);
    }

    cryptmode = OFF;
    chlngmode = ON;
    svr = make_Buffer(LNAME);
    usr = make_Buffer(LNAME);
    pas = make_Buffer(LNAME);

    for (i=1; i<argc; i++) {
        if      (!strcmp(argv[i], "-h")) {if (i!=argc-1) copy_s2Buffer(argv[i+1], &svr);}
        else if (!strcmp(argv[i], "-u")) {if (i!=argc-1) copy_s2Buffer(argv[i+1], &usr);}
        else if (!strcmp(argv[i], "-p")) {if (i!=argc-1) copy_s2Buffer(argv[i+1], &pas);}
        else if (!strcmp(argv[i], "-s")) cryptmode = ON;
        else if (!strcmp(argv[i], "-m")) chlngmode = OFF;
        else if (!strcmp(argv[i], "-d")) DebugMode = ON;
    }
    if (cryptmode==OFF) chlngmode = ON;

    hostname = awk_Buffer(svr, ':', 1);
    buf      = awk_Buffer(svr, ':', 2);
    if (buf.buf!=NULL) port = atoi((char*)buf.buf);
    else               port = PORT;
    free_Buffer(&svr);
    free_Buffer(&buf);

    if (cryptmode==ON) {
        err = check_auth(hostname, port, usr, pas, chlngmode, SSL_DH, SSL_AES128CBC, NULL, TRUE);
    }
    else {
        err = check_auth(hostname, port, usr, pas, chlngmode, 0, 0, NULL, FALSE);
    }

    if      (err==0) fprintf(stdout, "ok\n");
    else if (err==JBXL_ISNET_PASSWD_ERROR) fprintf(stdout, "np\n");
    else if (err==JBXL_ISNET_USER_ERROR)   fprintf(stdout, "nu\n");
    else jbxl_fprint_state(stderr, err);

    return err;
}


