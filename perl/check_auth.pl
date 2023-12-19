#!/usr/bin/perl

use perl_tuis_auth;

$a = perl_tuis_auth::check_auth("localhost", 9000, "username", "passwd", 0);

print "ret = $a\n";

