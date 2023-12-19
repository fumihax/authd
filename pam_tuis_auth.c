/*
認証サーバ用 PAM モジュール v1.3

	/etc/pam.d/system-auth
		auth        required      /lib/security/$ISA/pam_env.so
		auth        sufficient    /lib/security/$ISA/pam_tuis_auth.so authd.tuis.ac.jp:9000
		auth        required      /lib/security/$ISA/pam_deny.so
		.........

	参考：http://dolphin.c.u-tokyo.ac.jp/~naka7/pam.html
*/


#include	"pam_tuis_auth.h"





// パスワード認証
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	int ret;
	const char login_prompt[16]  = "login: ";
	const char passwd_prompt[16] = "password:";
	const char *user;

	struct pam_conv*     conv;
	struct pam_message   msg;
	struct pam_message*  pmsg;
	struct pam_response* resp;

	Buffer buf, srvr, hname, userid, passwd;
	int  port;
	tList* userlist=NULL;

	int   chlng_key = OFF;				// チャレンジキーは使わない
	int   remote_user_file  = FALSE;	// 指定した例外ファイルはローカルユーザ
	int   local_user_check  = FALSE;	// デフォルトは，リモートユーザ


	FILE* fp;
	fp = fopen("/tmp/pam.log", "w");

	if (argc<1) return PAM_SERVICE_ERR;

	srvr = make_Buffer(LNAME);
	copy_s2Buffer(argv[0], &srvr);

	hname = awk_Buffer(srvr, ':', 1);
	buf	  = awk_Buffer(srvr, ':', 2);
	if (buf.buf!=NULL) port = atoi((char*)buf.buf);
	else			   port = PORT;
	free_Buffer(&srvr);
	free_Buffer(&buf);

	//fprintf(fp, "host = %s  %d\n", hname.buf, port);
	//fflush(fp);


	if (argc>=2) {
		if (!strcasecmp("on", (const char*)argv[1])) {
			chlng_key = ON;				// チャレンジキーを使う
		}
	}
	if (argc>=3) {
		userlist = read_tList_file((char*)argv[2], 1);
		//fprintf(fp, "file = %s\n", argv[1]);
	}
	if (argc>=4) {
		if (!strcasecmp(RMT_KEYWRD, (const char*)argv[3])) {
			remote_user_file = TRUE; 	// 指定した例外ファイルはリモートユーザ
			local_user_check = TRUE;	// デフォルトは，ローカルユーザ
		}
	}


	// ユーザ名 
	ret = pam_get_user(pamh, &user, login_prompt);
	if (ret!=PAM_SUCCESS) {
		free_Buffer(&hname);
		return PAM_SERVICE_ERR;
	}
	userid = make_Buffer(LNAME);
	copy_s2Buffer(user, &userid);

	// パスワード入力メソッド(conv)
	ret = pam_get_item(pamh, PAM_CONV, (const void**)&conv);
	if (ret!=PAM_SUCCESS) {
		free_Buffer(&hname);
		free_Buffer(&userid);
		return PAM_SERVICE_ERR;
	}

	// エコーバックなしのパスワード入力 
	msg.msg_style = PAM_PROMPT_ECHO_OFF;
	msg.msg = passwd_prompt;
	pmsg = &msg;
	ret = conv->conv(1, (const struct pam_message **)&pmsg, &resp, conv->appdata_ptr);
	if (ret!=PAM_SUCCESS || resp==NULL) {
		free_Buffer(&hname);
		free_Buffer(&userid);
		return PAM_SERVICE_ERR;
	}
	if (resp->resp==NULL) {
		free_Buffer(&hname);
		free_Buffer(&userid);
		return PAM_SERVICE_ERR;
	}

	passwd = make_Buffer(LNAME);
	copy_s2Buffer((char*)(resp->resp), &passwd);


	if (!strcmp((char*)userid.buf, "root")) {		// root は必ずローカルユーザ
		local_user_check = TRUE;
	}
	else if (userlist!=NULL) {
		if (strncmp_tList(userlist, (char*)userid.buf, 0, 1)!=NULL) {		// リストにユーザ名が載っている
			if (remote_user_file==TRUE) {	//
				local_user_check = FALSE;
			}
			else {
				local_user_check = TRUE;
			}
		}
		del_all_tList(&userlist);
	}
		

	if (local_user_check) { 
		if (check_passwd((char*)passwd.buf, get_passwd((char*)userid.buf))) ret = 1;
		else ret = 0;
		//fprintf(fp, "Local Check %d\n", ret);
		//fflush(fp);
	}
	else {
		// 認証確認
		ret = check_auth(hname, port, userid, passwd, chlng_key, SSL_DH, SSL_AES128CBC, NULL, TRUE);
	}

	free_Buffer(&hname);
	free_Buffer(&userid);
	free_Buffer(&passwd);

	//fprintf(fp, "ret = %d\n", ret);
	//fflush(fp);
	//fclose(fp);

	if (ret==0) return PAM_SUCCESS;
	else        return PAM_SERVICE_ERR;
}




// パスワード設定
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
  	return PAM_SUCCESS;
}


