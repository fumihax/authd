#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT([authd], [4.1.0], [iseki@solar-system.tuis.ac.jp], [Authd])
AC_CONFIG_SRCDIR([authd.c])
AC_CONFIG_HEADER([config.h])

#AM_INIT_AUTOMAKE([authd], [4.0.0], [no-define])
AM_INIT_AUTOMAKE([subdir-objects])


AC_ARG_ENABLE(debug, AS_HELP_STRING([--enable-debug], [enable debug mode]), [
echo -n "checking debug mode... "
if test "$enableval" = "yes" ; then
    DEBUG="-DEBUG"
    AC_SUBST(DEBUG)
	echo "yes"
else
    echo "no"
fi
])


AC_ARG_ENABLE(pam, AS_HELP_STRING([--enable-pam], [build PAM module]), [
echo -n "checking build PAM module... "
ENABLE_PAM="$enableval"
if test "$enableval" = "yes" ; then
	echo "yes"
else
    echo "no"
fi
])
AM_CONDITIONAL(ENABLE_PAM, test "$ENABLE_PAM" = "yes")


AC_ARG_ENABLE(perl, AS_HELP_STRING([--enable-perl], [build Perl client module]), [
echo -n "checking build Perl module... "
ENABLE_PERL="$enableval"
if test "$enableval" = "yes" ; then
	echo "yes"
else
    echo "no"
fi
])
AM_CONDITIONAL(ENABLE_PERL, test "$ENABLE_PERL" = "yes")


AC_ARG_ENABLE(php,  AS_HELP_STRING([--enable-php=DIR], [build PHP client module]), [
echo -n "checking build PHP module... "
if test "$enableval" = "no" ; then
	echo "no"
else
    PHP_DIR="$enableval"
    if test "$PHP_DIR" = "yes" ; then
        PHP_DIR="/usr/include/php"
    fi
    echo "$PHP_DIR"
	if test ! -d $PHP_DIR ; then
		AC_MSG_ERROR([PHP source directory $PHP_DIR is not exist.])
	else
    	ENABLE_PHP="yes"
    	AC_SUBST(PHP_DIR)
	fi
fi
])
AM_CONDITIONAL(ENABLE_PHP, test "$ENABLE_PHP" = "yes")


AC_ARG_ENABLE(ssl, AS_HELP_STRING([--enable-ssl=DIR], [set SSL directory]), [
echo -n "checking SSL directory... "
if test "$enableval" = "no" ; then
    echo "no"
    AC_MSG_ERROR([this program needs SSL function.])
else
    SSL_DIR="$enableval"
    if test "$SSL_DIR" = "yes" ; then
        SSL_DIR="/usr"
    fi
    echo "$SSL_DIR"
    if test ! -d $SSL_DIR ; then
        AC_MSG_ERROR([SSL directory $SSL_DIR is not exist.])
	else
    	SSL_INC_DIR="-I${SSL_DIR}/include"
    	SSL_LIB_DIR="-L${SSL_DIR}/lib"
    	AC_SUBST(SSL_INC_DIR)
    	AC_SUBST(SSL_LIB_DIR)
    fi
fi
])  


AC_ARG_ENABLE(ldap, AS_HELP_STRING([--enable-ldap=DIR], [set LDAP directory]), [
echo -n "checking LDAP directory... "
if test "$enableval" = "no" ; then
    echo "no"
else
    LDAP_DIR="$enableval"
    if test "$LDAP_DIR" = "yes" ; then
        LDAP_DIR="/usr"
    fi
    echo "$LDAP_DIR"
    if test ! -d $LDAP_DIR ; then
        AC_MSG_ERROR([LDAP directory $LDAP_DIR is not exist.])
	else
    	LDAP_INC_DIR="-I${LDAP_DIR}/include"
    	LDAP_LIB_DIR="-L${LDAP_DIR}/lib"
		ENABLE_LDAP="-DENABLE_LDAP"
    	AC_SUBST(LDAP_INC_DIR)
    	AC_SUBST(LDAP_LIB_DIR)
    	AC_SUBST(ENABLE_LDAP)
	fi
fi
],[
# default
echo "checking enable ldap function ... no"
])  


# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_RANLIB


# Checks for libraries.
# FIXME: Replace `main' with a function in `-lcrypt':
AC_CHECK_LIB([crypt], [main])
# FIXME: Replace `main' with a function in `-lcrypto':
AC_CHECK_LIB([crypto], [main])
# FIXME: Replace `main' with a function in `-lm':
AC_CHECK_LIB([m], [main])
# FIXME: Replace `main' with a function in `-lnsl':
#AC_CHECK_LIB([nsl], [main])
# FIXME: Replace `main' with a function in `-lpam':
AC_CHECK_LIB([pam], [main])
# FIXME: Replace `main' with a function in `-lssl':
AC_CHECK_LIB([ssl], [main])
# FIXME: Replace `main' with a function in `-lldap -lber':
AC_CHECK_LIB([ldap], [main])
AC_CHECK_LIB([lber], [main])
# FIXME: Replace `main' with a function in `-lsocket':
AC_CHECK_LIB([socket], [main])


# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([pam/pam_appl.h security/pam_appl.h ldap.h openssl/ssl.h locale.h shadow.h string.h syslog.h unistd.h])


# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_CONST
AC_TYPE_PID_T

# Checks for library functions.
AC_FUNC_FORK
AC_TYPE_SIGNAL
AC_CHECK_FUNCS([localeconv strcasecmp])


AC_CONFIG_FILES([Makefile
                 php/Makefile])

AC_OUTPUT

