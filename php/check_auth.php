<?php

$host = "202.26.144.41";
$port = "9000";
$userid = "iseki";
$pass = "xxxx";

//dl("/usr/lib64/php/modules/php_tuis_auth.so");
dl("php_tuis_auth.so");

//
$ret = -1;
if (function_exists('check_auth')){
    $ret = check_auth($host, $port, $userid, $pass, 0);
}

/*
$com = "/usr/local/bin/check_auth -h ".$host.":".$pot." -u $userid -p $pass -m -s";
$ret = exec($com);
*/

/**
RET : -1  error
RET : 1   ok
RET : 2   password error
RET : 3   not exist user
*/
print "RET = $ret\n";

