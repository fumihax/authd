
#ifndef _AUTH_SERVER_H
#define _AUTH_SERVER_H


#define  ARGHELP "\n\
  -p : 続いてポート番号を指定する．\n\
  -k : 続いてキー保存ファイル名を指定する．\n\
  -a : 続いて接続許可ファイル名を指定する．\n\
  -f : 続いてプロセスIDファイル名を指定する．\n\
  -i : started by inetd (no daemon mode)\n\
  -s : セキュアモード（強制暗号化モード)\n\
  -m : チャレンジキーを交換しない．この場合，必ずセキュアモードになる．\n\
  -l : LADP & AD モード. この場合，必ずセキュアモードかつチャレンジキーを交換しないモードになる．\n\
  -d : デバッグモード\n\
  -n : no check mode\n\
  -h : ヘルプ表示\n\
  -v : バージョン表示\n\
\n"


#include "password.h"
#include "ssl_tool.h"
#include "dh_tool.h"
#include "ipaddr_tool.h"
#include "isnet.h"

#ifdef ENABLE_LDAP
	#include "ldap_tool.h"
#endif


#define  ALLOW_FILE   "/usr/local/etc/authd/authd.allow"
#define  DHKEY_FILE   "/usr/local/etc/authd/dhkey"

#define  TIME_OUT 20         	// サーバタイムアウト（秒） 


extern int  PortNo;
extern int  Socket;
extern int  DaemonMode;
extern int  NoCheckMode;
extern int  SecureMode;



void  receipt(int, struct sockaddr_in);             // コマンド受け付け 
int   command_pase(Buffer, int); 					// コマンド解釈 

void  interrupt(int);


#endif

