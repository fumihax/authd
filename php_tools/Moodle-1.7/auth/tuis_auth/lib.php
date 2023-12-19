<?PHP

global $CFG;

$CFG->auth_user_create = $CFG->auth_tuis_usercreate;


function auth_user_login($username, $password) 
{
    global $CFG;

    $host = $CFG->auth_tuis_host;
    $port = $CFG->auth_tuis_port;

	dl("php_tuis_auth.so");

	if (1 == tuis_check_auth($host, $port, $username, $password, 0)) {
        return true;
    } 
	else {
        return false;
    }
}



/**
 *
 *
*/
function auth_user_exists($username) 
{
    global $CFG;

	// forbidden user name
	//if (preg_match('/^[a-z]\d\d\d\d\d[a-z][a-z]$/', $username)) return true;

    $host = $CFG->auth_tuis_host;
    $port = $CFG->auth_tuis_port;

	dl("php_tuis_auth.so");

	if (2 == tuis_check_auth($host, $port, $username, "passwd", 0)) {
        return true;
    } 
	else {
        return false;
    }
}




/**
 *
 * Transration rule from exact username to username for display
 *
*/
function auth_trans_username($username) 
{
	if (preg_match('/^[a-z]\d\d\d\d\d[a-z][a-z]$/', $username)) {
		$username = substr($username, 0, 6);
	}

	return $username;
}

?>
