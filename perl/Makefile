# vi: set tabstop=4 nocindent paste: 


VERSION = 1.2


PERL_MODNAME = perl_tuis_auth


#
#
SUBJ = $(PERL_MODNAME).so 
#
all: $(SUBJ)

#
CC   = gcc
AR   = ar
TH	 = touch

LIB_BSC_DIR = ../../JunkBox_Lib/Lib
LIB_EXT_DIR = ../../JunkBox_Lib/xLib

LIB_BSC = $(LIB_BSC_DIR)/libbasic.a
LIB_EXT = $(LIB_EXT_DIR)/libextend.a


CFLAGS  = -fPIC -I.. -DVERSION=\"Version\ $(VERSION)\\n\"

SLIB = -L$(LIB_BSC_DIR) -lbasic -lm
ELIB = -L$(LIB_EXT_DIR) -lextend
#
#
#

.h.c:
	$(TH) $@


.c.o:
	$(CC) $< $(CFLAGS) -c -O2 


#
#
#
#
check_auth_bystr.o:
	(cd ../ && make check_auth_bystr.o)
	ln -s ../check_auth_bystr.o .


$(PERL_MODNAME).so: check_auth_bystr.o ../check_auth_bystr.h $(LIB_BSC) $(LIB_EXT)
	(cd $(PERL_MODNAME) && perl Makefile.PL && make)




$(LIB_BSC):
	(cd $(LIB_BSC_DIR) && make)

$(LIB_EXT):
	(cd $(LIB_EXT_DIR) && make)


install: 
	(cd $(PERL_MODNAME) && make install)


test:
	(cd $(PERL_MODNAME) && make test)



clean:
	rm -f *.o *.so *.pm *~ $(SUBJ)  
	-(cd $(PERL_MODNAME) && rm -f *~ Makefile.old && make clean)
 

backup:
	(cd .. && make backup)


dist dist-all:
	(cd .. && make dist)

