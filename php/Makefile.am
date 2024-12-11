# vi: set tabstop=4 nocindent paste: 
#
# ./configure --enable-php=/usr/local/src/php-4.4.2
#


PHP_INC = @PHP_DIR@


VERSION = 1.2



LIB_TOP_DIR = ../../JunkBox_Lib
LIB_BSC_DIR = $(LIB_TOP_DIR)/Lib
LIB_EXT_DIR = $(LIB_TOP_DIR)/xLib

LIB_BSC = $(LIB_BSC_DIR)/libbasic.a
LIB_EXT = $(LIB_EXT_DIR)/libextend.a


SUBJ = php_jbxl_auth.so 

PHP_CFLAGS = -DCOMPILE_DL -I$(PHP_INC) -I$(PHP_INC)/main -I$(PHP_INC)/TSRM -I$(PHP_INC)/Zend
AM_CFLAGS  = -fPIC -W -Wall -I$(LIB_BSC_DIR) -I$(LIB_EXT_DIR) -DVERSION=\"Version\ $(VERSION)\\n\" $(PHP_CFLAGS)

bin_PROGRAMS  = $(SUBJ)

php_jbxl_auth_so_SOURCES = php_jbxl_auth.c
php_jbxl_auth_so_LDADD = ../check_auth_bystr.o $(LIB_EXT) $(LIB_BSC) 
php_jbxl_auth_so_LDFLAGS = -shared




install:


clean:
	rm -f *.o *.so *~ $(SUBJ)
 

clean_deps:
	-rm -rf .deps 



dist dist-all:
	(cd .. && make dist)


backup:
	(cd .. && make backup)



$(LIB_BSC):
	(cd $(LIB_BSC_DIR) && make)


$(LIB_EXT):
	(cd $(LIB_EXT_DIR) && make)



