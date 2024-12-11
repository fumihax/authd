# vi: set tabstop=4 nocindent: 


LIB_TOP_DIR = ../JunkBox_Lib
LIB_BSC_DIR = $(LIB_TOP_DIR)/Lib
LIB_EXT_DIR = $(LIB_TOP_DIR)/xLib

LIB_BSC = $(LIB_BSC_DIR)/libbasic.a
LIB_EXT = $(LIB_EXT_DIR)/libextend.a


SUBJ = authd  check_auth 
if ENABLE_PAM
    SUBJ += pam_jbxl_auth.so
endif

AM_CFLAGS = -fPIC -W -Wall -I$(LIB_BSC_DIR) -I$(LIB_EXT_DIR)
AM_CFLAGS += @DEBUG@ @SSL_INC_DIR@ @LDAP_INC_DIR@ @ENABLE_LDAP@ -DENABLE_SSL

bin_PROGRAMS  = $(SUBJ)

authd_SOURCES = authd.c
check_auth_SOURCES = check_auth.c

authd_LDADD = $(LIB_EXT) $(LIB_BSC) 
check_auth_LDADD = $(LIB_EXT) $(LIB_BSC)

if ENABLE_PAM
    pam_jbxl_auth_so_SOURCES = pam_jbxl_auth.c
    pam_jbxl_auth_so_LDADD = $(LIB_EXT) $(LIB_BSC)
    pam_jbxl_auth_so_LDFLAGS = -shared @SSL_LIB_DIR@ @LDAP_LIB_DIR@
endif



TARGET = check_auth_bystr.o
if ENABLE_PERL
    TARGET += perl-mod
endif
if ENABLE_PHP
    TARGET += php-mod
endif

all: $(TARGET)



install: $(SUBJ)
	$(INSTALL_PROGRAM) -m 4755 authd  /usr/local/bin
	$(INSTALL_PROGRAM) -m 0755 check_auth  /usr/local/bin
	$(INSTALL_PROGRAM) -m 0755 conf/authd.init  /etc/init.d/authd
	mkdir -p /var/run
	mkdir -p /usr/local/etc/authd
	chmod  0700 /usr/local/etc/authd
if ENABLE_PAM
	$(INSTALL_PROGRAM) -m 0755 pam_jbxl_auth.so /lib/security/
endif
if ENABLE_PERL
	(cd perl && make install)
endif


php-mod:
	(cd php && make)


perl-mod:
	(cd perl && make)



clean:
	rm -f *.o *.so *~ $(SUBJ) conf/*~
	-(cd perl && make clean)
	-(cd php  && make clean)
 

clean_deps:
	-rm -rf .deps
if ENABLE_PHP
	-(cd php  && make clean_deps)
endif



$(LIB_BSC):
	(cd  $(LIB_BSC_DIR) && make)


$(LIB_EXT):
	(cd  $(LIB_EXT_DIR) && make)





##########################################################################################################
#
# for Distribute
#
DIST_DIR = ../Dist
DIST_WRK = ../.temp_Dist
DIST_EXT = tar.gz

EXTRA_DIST = *.c *.h conf php perl perl/perl_jbxl_auth perl/perl_jbxl_auth/t perl/perl_jbxl_auth/lib README.euc Protocol INSTALL

PKG_NAME = $(PACKAGE_NAME)-$(PACKAGE_VERSION)


pkg:
	make clean
	make dist
	zcat  $(PKG_NAME).tar.gz | tar xfp -
	chmod o-rwx $(PKG_NAME)
	(cd $(PKG_NAME) && find . -name ".deps"|xargs rm -rf)
	tar cfp - $(PKG_NAME) | gzip > ../$(PKG_NAME).$(DIST_EXT)
	rm -rf $(PKG_NAME)
	rm -f $(PKG_NAME).$(DIST_EXT)


dist-pkg release:
	mkdir -p $(DIST_DIR)
	mkdir -p $(DIST_WRK)
	(cd $(DIST_WRK) && cp -Rpd ../JunkBox_Lib/ .)
	(cd $(DIST_WRK) && cp -Rpd ../$(PACKAGE_NAME) $(PKG_NAME))
	(cd $(DIST_WRK) && find . -name ".svn" | xargs rm -rf)
	(cd $(DIST_WRK) && cd JunkBox_Lib && make pkg)
	(cd $(DIST_WRK) && cd $(PKG_NAME) && make pkg)
	(cd $(DIST_WRK) && rm -rf JunkBox_Lib $(PKG_NAME))
	(cd $(DIST_WRK) && zcat junkbox_lib-*.$(DIST_EXT)  | tar xfp -)
	(cd $(DIST_WRK) && zcat $(PKG_NAME).$(DIST_EXT) | tar xfp -)
	(cd $(DIST_WRK) && rm -rf junkbox_lib-*.$(DIST_EXT) $(PKG_NAME).$(DIST_EXT))
	(cd $(DIST_WRK) && mv $(PKG_NAME)/INSTALL INSTALL)
	(cd $(DIST_WRK) && chmod -R o-rwx .)
	(cd $(DIST_WRK) && tar cfp - * | gzip > $(PKG_NAME).$(DIST_EXT))
	(cd $(DIST_WRK) && rm -f INSTALL JunkBox_Lib)
	(cd $(DIST_WRK) && rm -rf junkbox_lib-* $(PKG_NAME))
	mv $(DIST_WRK)/$(PKG_NAME).$(DIST_EXT) $(DIST_DIR)

