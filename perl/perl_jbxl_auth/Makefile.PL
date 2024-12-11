use 5.008000;
#use 5.008002;
use ExtUtils::MakeMaker;

# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    NAME              => 'perl_jbxl_auth',
    VERSION_FROM      => 'lib/perl_jbxl_auth.pm', # finds $VERSION
    PREREQ_PM         => {}, # e.g., Module::Name => 1.1
    ($] >= 5.005 ?     ## Add these new keywords supported since 5.005
      (ABSTRACT_FROM  => 'lib/perl_jbxl_auth.pm', # retrieve abstract from module
       AUTHOR         => 'Fumi.Iseki <fumi.hax@gmail.com>') : ()),
    LIBS              => ['-L../../../JunkBox_Lib/xLib -lextend -L../../../JunkBox_Lib/Lib -lbasic -lm -lcrypto -lssl -lcrypt'], 
    DEFINE            => '', # e.g., '-DHAVE_SOMETHING'
    INC               => '-I. -I..', # e.g., '-I. -I/usr/include/other'
	# Un-comment this if you add C files to link with later:
    OBJECT            => '$(O_FILES) ../check_auth_bystr.o', # link all the C files too
);

#
