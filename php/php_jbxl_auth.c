/*
  for PHP Version 5/7/8
*/

#define PHP_JBXL_AUTH_VERSION "1.1.0" 

#include "php.h"
#include "check_auth_bystr.h"
#include "jbxl_state.h"

#if PHP_MAJOR_VERSION >= 7
  #define PHP_V7
  #define ZTS
#endif
#if PHP_MAJOR_VERSION >= 8
  #define PHP_V8
#endif


PHP_FUNCTION(check_auth)
{
    char*  host;
    long   port;
    char*  user;
    char*  pass;
    long   chmode;

#ifdef PHP_V7        // for PHP7/8
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
    else if (cc==JBXL_JBXL_PASSWD_ERROR) ret = 2;
    else if (cc==JBXL_JBXL_USER_ERROR)   ret = 3;
    else ret = cc;

    RETURN_LONG((long)ret);
}


// for PHP8
#ifdef PHP_V8
ZEND_BEGIN_ARG_INFO(check_auth_arginfo, 0)
ZEND_ARG_TYPE_INFO(0, host, IS_STRING, 0)
ZEND_ARG_TYPE_INFO(0, port, IS_LONG, 1)
ZEND_ARG_TYPE_INFO(0, user, IS_STRING, 2)
ZEND_ARG_TYPE_INFO(0, pass, IS_STRING, 3)
ZEND_ARG_TYPE_INFO(0, chmode, IS_LONG, 4)
ZEND_END_ARG_INFO()
#endif


/*
関数名は アンダーバー _ が2個の場合は駄目の様 何で？
*/
const zend_function_entry php_jbxl_auth_functions[] =
{
#ifdef PHP_V7        // for PHP7/8
    PHP_FE(check_auth, check_auth_arginfo)
    PHP_FE_END
#else
    PHP_FE(check_auth, NULL) {NULL, NULL, NULL}
#endif
};


zend_module_entry php_jbxl_auth_module_entry =
{
    STANDARD_MODULE_HEADER,
    "php_jbxl_auth",
    php_jbxl_auth_functions,
    NULL, //PHP_MINIT(php_jbxl_auth),
    NULL, //PHP_MSHUTDOWN(php_jbxl_auth),
    NULL, //PHP_RINIT(php_jbxl_auth),
    NULL, //PHP_RSHUTDOWN(php_jbxl_auth),
    NULL, //PHP_MINFO(php_jbxl_auth),
    PHP_JBXL_AUTH_VERSION,
    STANDARD_MODULE_PROPERTIES
};


#ifdef ZTS
ZEND_TSRMLS_CACHE_DEFINE()
#endif

ZEND_GET_MODULE(php_jbxl_auth)


