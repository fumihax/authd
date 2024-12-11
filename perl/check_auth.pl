#!/usr/bin/perl

use perl_jbxl_auth;

$a = perl_jbxl_auth::check_auth("localhost", 9000, "username", "passwd", 0);

print "ret = $a\n";

