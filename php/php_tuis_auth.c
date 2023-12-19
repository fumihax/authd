/*
  for PHP Version 5/7                                                     |
*/

#define PHP_TUIS_AUTH_VERSION "1.0.0" 


#include "php.h"
#include "check_auth_bystr.h"
#include "jbxl_state.h"

#define ZTS 


PHP_FUNCTION(check_auth)
{
    char*  host;
    long   port;
    char*  user;
    char*  pass;
    long   chmode;

#ifdef PHP_FE_END    // for PHP7
    size_t lhost;    // 文字の長さ
    size_t luser;
    size_t lpass;
#else
    int    lhost;    // 文字の長さ
    int    luser;
    int    lpass;
#endif

    int    ret, cc;

    if (zend_parse_parameters(ZEND_NUM_ARGS(), "slssl", &host, &lhost, &port, &user, &luser, &pass, &lpass, &chmode) == FAILURE) {
        return;
    }

    cc = check_auth_bystr(host, (int)port, user, pass, (int)chmode);
    if      (cc==0) ret = 1;
    else if (cc==JBXL_ISNET_PASSWD_ERROR) ret = 2;
    else if (cc==JBXL_ISNET_USER_ERROR)   ret = 3;
    else ret = cc;

    RETURN_LONG((long)ret);
}



/*
関数名は アンダーバー _ が2個の場合は駄目の様 何で？
*/
const zend_function_entry php_tuis_auth_functions[] =
{
#ifdef PHP_FE_END    // for PHP7
    PHP_FE(check_auth, NULL)
    PHP_FE_END
#else
    PHP_FE(check_auth, NULL) {NULL, NULL, NULL}
#endif
};



zend_module_entry php_tuis_auth_module_entry =
{
    STANDARD_MODULE_HEADER,
    "php_tuis_auth",
    php_tuis_auth_functions,
    NULL, //PHP_MINIT(php_tuis_auth),
    NULL, //PHP_MSHUTDOWN(php_tuis_auth),
    NULL, //PHP_RINIT(php_tuis_auth),
    NULL, //PHP_RSHUTDOWN(php_tuis_auth),
    NULL, //PHP_MINFO(php_tuis_auth),
    PHP_TUIS_AUTH_VERSION,
    STANDARD_MODULE_PROPERTIES
};


#ifdef ZTS
ZEND_TSRMLS_CACHE_DEFINE()
#endif

ZEND_GET_MODULE(php_tuis_auth)


