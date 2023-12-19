/* vi:set tabstop=4 noautoindent nocindent: */

/** 
認証サーバ Ver 3.4.0

    Diffie-Hellman 対応

*/


#include "authd.h"


int   PortNo      = 9000;      // デフォルトポート番号 
int   DaemonMode  = ON;
int   NoCheckMode = OFF;
int   SecureMode  = OFF;
int   NoChlngMode = OFF;
int   ADLdapMode  = OFF;



tList* Allow_IPaddr = NULL;

char*  IPaddr;
char*  MnName;
char*  Unknown_User = "unknown user";

unsigned char*  IPaddr_num;




/*
  コマンド解釈部
*/
int command_pase(Buffer mesg, int sock)
{
    int     endflag = OFF;
    Buffer  buf, dec, command, operand, comment;
    char*   user_id;


    buf = make_Buffer(LBUF);
    dec = get_plain_sBuffer(mesg, CRYPT_SharedKey, CRYPT_Type);
    chomp_Buffer(&dec);
    command = get_command(dec);
    operand = get_operand(dec);
    comment = get_comment(dec);
    DEBUG_MODE print_message("CLIENT = %s\n", dec.buf);
    free_Buffer(&dec);


    if (!strcasecmp("HELLO", (char*)command.buf)){
        command_HELLO(operand, comment, sock);
    }

    else if (!strcasecmp("KEYEX", (char*)command.buf)){
        command_KEYEX(operand, comment, sock);
    }

    else if (!strcasecmp("CRYPT", (char*)command.buf)){
        command_CRYPT(operand, comment, sock);
    }

    else if (!strcasecmp("USERID", (char*)command.buf)){
        if (NoCheckMode==ON) {  // デバッグ用 常にOKを返す
            tcp_send_crypt_mesg(sock, "OK\r\n", CRYPT_SharedKey, CRYPT_Type);
            DEBUG_MODE print_message("SERVER = OK by NoCheckMode.\n");
        }
        else if (SecureMode==ON && CRYPT_SharedKey==NULL) {
            tcp_send_crypt_mesg(sock, "ERR 801 Secure Mode required CRYPT connection.\r\n", CRYPT_SharedKey, CRYPT_Type);
            DEBUG_MODE print_message("ERR 801 Secure Mode required CRYPT connection.\n");
            endflag = ON;
            //socket_close(sock);
        }
        else if (NoChlngMode==ON && No_isNet_Chlng==FALSE) {
            tcp_send_crypt_mesg(sock, "ERR 802 Use NOCHLNG command.\r\n", CRYPT_SharedKey, CRYPT_Type);
            DEBUG_MODE print_message("ERR 802 Use NOCHLNG command.\n");
            endflag = ON; 
            //socket_close(sock);
        }    
        else if (CRYPT_SharedKey==NULL && No_isNet_Chlng==TRUE) {
            tcp_send_crypt_mesg(sock, "ERR 803 CRYPT Algorism required at NOCHLNG connection.\r\n", CRYPT_SharedKey, CRYPT_Type);
            DEBUG_MODE print_message("ERR 803 CRYPT Algorism required at NOCHLNG connection.\n");
            endflag = ON; 
            //socket_close(sock);
        }    
        else {
            command_USERID(operand, comment, sock);
        }
    }

    else if (!strcasecmp("PASSWD", (char*)command.buf)){ 
        if (NoCheckMode==ON) {
            tcp_send_crypt_mesg(sock, "OK\r\n", CRYPT_SharedKey, CRYPT_Type);
            DEBUG_MODE print_message("SERVER = OK by NoCheckMode.\n");
        }
        else {
            command_PASSWD(operand, comment, sock);
        }
    }

    else if (!strcasecmp("BYE", (char*)command.buf)){ 
        command_BYE(operand, comment, sock);
        endflag = ON;
    }

    else {
        copy_s2Buffer("ERR 988 Unknown Command: ", &buf);
        cat_Buffer(&command, &buf);
        cat_s2Buffer(".\r\n", &buf);
        //tcp_send_sBufferln(sock, &buf);
        tcp_send_crypt_mesg(sock, (char*)buf.buf, CRYPT_SharedKey, CRYPT_Type);
        endflag = ON;

        if (User_ID==NULL) user_id = Unknown_User;
        else               user_id = (char*)User_ID->buf;
        syslog(LOG_INFO, "[%s] %s: %s", IPaddr, user_id, buf.buf);
        DEBUG_MODE print_message("[%s] %s: %s", IPaddr, user_id, buf.buf);
    }


    if (endflag==ON) {
        socket_close(sock);
        if (User_ID==NULL) user_id = Unknown_User;
        else               user_id = (char*)User_ID->buf;
        syslog(LOG_INFO, "[%s] %s: session end.\n", IPaddr, user_id);
        DEBUG_MODE print_message("[%s] %s: session end.\n", IPaddr, user_id);
        exit(0);
    }

    free_Buffer(&buf);
    free_Buffer(&command);
    free_Buffer(&operand);
    free_Buffer(&comment);

    return 0;
}



/*
  main関数
  -p : 続いてポート番号を指定する．
  -k : 続いてキー保存ファイル名を指定する．
  -a : 続いて接続許可ファイル名を指定する．
  -f : 続いてプロセスIDファイル名を指定する．
  -i : started by inetd (no daemon mode)
  -s : セキュアモード（強制暗号化モード)
  -m : チャレンジキーを交換しないモードでのみ動作．セキュアモード指定した場合のみ有効
  -l : AD & LDAP モード．強制的にセキュアモード＆チャレンジキー非交換モードになる．
  -d : デバッグモード
  -n : no check mode
  -h : ヘルプ表示
  -v : バージョン表示
*/
int main(int argc, char** argv)
{   
    int       i, port=0;
    int       sofd, nsofd;
    socklen_t cdlen;
    struct sockaddr_in cl_addr;
    Buffer pki, dhkeyfile, allowfile, pidfile;

    dhkeyfile = make_Buffer(LNAME);
    allowfile = make_Buffer(LNAME);
    pidfile   = make_Buffer(LNAME);
    for (i=1; i<argc; i++) {
        if        (!strcasecmp(argv[i],"-p")) {if (i!=argc-1) port = atoi(argv[i+1]);}
        else if (!strcasecmp(argv[i],"-k")) {if (i!=argc-1) copy_s2Buffer(argv[i+1], &dhkeyfile);}
        else if (!strcasecmp(argv[i],"-a")) {if (i!=argc-1) copy_s2Buffer(argv[i+1], &allowfile);}
        else if (!strcasecmp(argv[i],"-f")) {if (i!=argc-1) copy_s2Buffer(argv[i+1], &pidfile);}
        else if (!strcasecmp(argv[i],"-d")) DebugMode   = ON;                     
        else if (!strcasecmp(argv[i],"-i")) DaemonMode  = OFF;                     
        else if (!strcasecmp(argv[i],"-n")) NoCheckMode = ON;                     
        else if (!strcasecmp(argv[i],"-s")) SecureMode  = ON;                     
        else if (!strcasecmp(argv[i],"-m")) NoChlngMode = ON;                     
        else if (!strcasecmp(argv[i],"-l")) ADLdapMode  = ON;                     
        else if (!strcasecmp(argv[i],"-v")) {fprintf(stderr, "%s\n", PACKAGE_VERSION); exit(0);}
        else if (!strcasecmp(argv[i],"-h")) {fprintf(stderr, "%s\n", ARGHELP); exit(0);}
        else if (!strcasecmp(argv[i],"-help")) {fprintf(stderr, "%s\n", ARGHELP); exit(0);}
    }
    if (port==0) port = PortNo;
    else         PortNo = port;
    if (dhkeyfile.buf[0]=='\0') copy_s2Buffer(DHKEY_FILE, &dhkeyfile);
    if (allowfile.buf[0]=='\0') copy_s2Buffer(ALLOW_FILE, &allowfile);

    //
    if (SecureMode==OFF) NoChlngMode = OFF ;
    if (ADLdapMode==ON) {
#ifndef ENABLE_LDAP
        print_message("ERROR: -l option is specified, but LDAP function is disabled in authd\n");
        print_message("ERROR: please re-configure with --enable-ldap option and re-make. exit!!\n");
        exit(1);
#endif
        SecureMode  = ON;
        NoChlngMode = ON;
        Use_isNet_Ldap = TRUE;
    }
    if (NoChlngMode==ON) {
        No_isNet_Chlng = TRUE;
    }

    DEBUG_MODE {
        print_message("Challenge Key Mode: ");
        if (NoChlngMode==OFF) print_message("ON\n");
        else                  print_message("OFF\n");;
        print_message("Secure Mode:        ");
        if (SecureMode==ON)   print_message("ON\n");
        else                  print_message("OFF\n");
        print_message("LDAP Mode:          ");
        if (ADLdapMode==ON)   print_message("ON\n");
        else                  print_message("OFF\n");
    }

//  signal(SIGCHLD, SIG_IGN);
    set_sigterm_child(NULL);
    signal(SIGINT, interrupt);

//  openlog("Authd", LOG_PERROR|LOG_PID, LOG_AUTH); // open syslog 
    openlog("Authd", LOG_PID, LOG_AUTH);            // open syslog 

    Allow_IPaddr = read_ipaddr_file((char*)allowfile.buf);

    DEBUG_MODE print_message("DH暗号化キー作成中\n");
    Base64_DHspki = new_Buffer(0);
    pki = get_DHspki_ff((char*)dhkeyfile.buf, 1024, &DHkey);
    *Base64_DHspki = encode_base64_Buffer(pki);
    free_Buffer(&pki);
    free_Buffer(&dhkeyfile);
    free_Buffer(&allowfile);
    DEBUG_MODE print_message("DH暗号化キー作成終了\n");

    sofd  = tcp_server_socket(port);
    cdlen = sizeof(cl_addr);

    // PIDファイルの作成
    if (pidfile.buf[0]!='\0') {
        FILE*  fp;
        pid_t  pid;
        fp = fopen((char*)pidfile.buf, "w");
        if (fp!=NULL) {
            pid = getpid();
            fprintf(fp, "%d", (int)pid);
            fclose(fp);
        }
        free_Buffer(&pidfile);
    }

//
#ifdef ENABLE_LDAP
    JBXL_LDAP_Host  ldap_host;
    JBXL_LDAP_Dn    ldap_bind;

    if (ADLdapMode==ON) {
        read_ldap_config(NULL, &ldap_host, &ldap_bind);

        DEBUG_MODE {
            print_message("LDAP Host Name : ");
            if (ldap_host.hostname.buf!=NULL) print_message("%s", ldap_host.hostname.buf);
            print_message(":%d\n", ldap_host.port);
            print_message("LDAP Protocol  : ");
            if (ldap_host.useSSL==TRUE) print_message("ldaps\n");
            else print_message("ldap\n");

            print_message("LDAP Base      : ");
            if (ldap_bind.base.buf!=NULL) print_message("%s", ldap_bind.base.buf);
            print_message("\n");
            print_message("LDAP Dn Name   : ");
            if (ldap_bind.dnbind.buf!=NULL) print_message("%s", ldap_bind.dnbind.buf);
            print_message("\n");
            print_message("LDAP Dn Passwd : ");
            if (ldap_bind.passwd.buf!=NULL) print_message("%s\n", ldap_bind.passwd.buf);
            else print_message("NULL\n");
        }
    }
#endif


//    seteuid(-2);
    DEBUG_MODE print_message("Wating connection from clients .....\n");
    if (DaemonMode==ON) {
        Loop{
            nsofd = accept_intr(sofd, (struct sockaddr*)&cl_addr, &cdlen);
            if (nsofd<0) Error("accept");
            if (fork()==0) receipt(nsofd, cl_addr);
            close(nsofd);
        }
    }
    else {
        nsofd = accept_intr(sofd, (struct sockaddr*)&cl_addr, &cdlen);
        if (nsofd<0) Error("accept");
        receipt(nsofd, cl_addr);
        close(nsofd);
        close(sofd);
    }

    return 0;
}



/*  
  クライアントからの命令待ち受け部
*/
void  receipt(int sofd, struct sockaddr_in addr)
{
    int    cc;
    Buffer buf, msg;

    //CRYPT_Algorism = 0;
    IPaddr_num = get_ipaddr_num_ipv4(addr.sin_addr);
    IPaddr     = get_ipaddr_ipv4(addr.sin_addr);
    MnName     = get_hostname_bynum_ipv4(IPaddr_num);

    init_rand();

    if (Allow_IPaddr!=NULL) {
        if (!is_host_in_list(Allow_IPaddr, IPaddr_num, MnName)) {
            syslog(LOG_INFO, "[%s] access denied.\n", IPaddr);
            DEBUG_MODE print_message("[%s] access denied.\n", IPaddr);
            socket_close(sofd);
            exit(1);
        }
    }

    syslog(LOG_INFO, "[%s] session start.\n", IPaddr);
    DEBUG_MODE print_message("[%s] session start.\n", IPaddr);


    msg = make_Buffer(LBUF);
    buf = make_Buffer(LBUF);

    do {
        cc = tcp_recv_Buffer_wait(sofd, &buf, TIME_OUT);
        if(cc>0) {
            cc = cat_Buffer(&buf, &msg);
            if (buf.buf[cc-1]==CHAR_LF) {
                command_pase(msg, sofd);
                clear_Buffer(&msg);
            }
            clear_Buffer(&buf);
        }
    } while (cc>0);


    if (cc<0) {
        tcp_send_mesgln(sofd, "ERR 999 Time Out.");
        syslog(LOG_INFO, "[%s] time out.\n", IPaddr);
        DEBUG_MODE print_message("[%s] time out.\n",  IPaddr);
    }
  

    close(sofd);
    syslog(LOG_INFO, "[%s] session end.\n", IPaddr);
    DEBUG_MODE print_message("[%s] session end.\n", IPaddr);

    free_Buffer(&buf);
    free_Buffer(&msg);
    free(IPaddr);
    free(IPaddr_num);
    free(MnName);

    exit(0);
}        



void  interrupt(int signal)
{
    exit(signal);
}

