/*

参考：http://dolphin.c.u-tokyo.ac.jp/~naka7/pam.html
*/



#include <stdio.h>
#include <string.h>


#include "isnet.h"
#include "tlist.h"
#include "password.h"



#define PAM_SM_AUTH
#define _PAM_EXTERN_FUNCTIONS


#ifdef HAVE_SECURITY_PAM_APPL_H
	#include <security/pam_appl.h>
	#include <security/pam_modules.h>
#endif
#ifdef HAVE_PAM_PAM_APPL_H
	#include <pam/pam_appl.h>
	#include <pam/pam_modules.h>
#endif



#define PASS_LENGTH 32
#define PORT 9000

#define RMT_KEYWRD "remote"



#ifdef PAM_STATIC

struct pam_module _pam_easypasswd_modstruct = {
	"pam_tuis_auth",
	pam_sm_authenticate,
	pam_sm_setcred,
	NULL,
	NULL,
	NULL,
	NULL,
};

#endif



#ifndef PAM_EXTERN
	#ifdef PAM_STATIC
		#define PAM_EXTERN static
	#else
		#define PAM_EXTERN extern
	#endif
#endif

// パスワード認証
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv);

// パスワード設定
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv);



