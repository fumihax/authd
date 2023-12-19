<?php
/*
Plugin Name: TUIS Auth
Plugin URI: http://www.nsl.tuis.ac.jp/ 
Description: Login Plugin for TUIS
Version: 1.0.1
Author: Fumi Iseki
*/


// setting menu
function  tuis_auth_menu()
{
	include 'tuis_auth_admin.php';
}



function  tuis_auth_admin_actions()
{
	add_options_page('TUIS Auth', 'TUIS Auth', 10, 'tuis_auth', 'tuis_auth_menu');
}



function  tuis_auth_activation_hook()
{
	add_option('tuis_auth_server_fqdn', 'localhost');
	add_option('tuis_auth_server_port', '9000');
}



// authenticate function
function  tuis_auth_authenticate($user, $lgname, $passwd) 
{
	if (is_a($user, 'WP_User')) return $user;	// 認証済み
	$error = new WP_Error();

	//
	if (empty($lgname) || empty($passwd)) {
		if (empty($lgname)) $error->add('empty_login_name', __('<strong>ERROR</strong>: login name is empty.'));
		if (empty($passwd)) $error->add('empty_password',   __('<strong>ERROR</strong>: password is empty.'));
		return $error;
	}
	
	//
	if (!function_exists('tuis_check_auth')) {
		$error->add('not_exist_function', __('<strong>ERROR</strong>: tuis_check_auth function does not exist.'));
		return $error;
	}

	//
	$server_fqdn = get_option('tuis_auth_server_fqdn');
	$server_port = intval(get_option('tuis_auth_server_port'));

	if (empty($server_fqdn) || $server_port<0) {
		if (empty($server_fqdn)) $error->add('empty_server_fqdn', __('<strong>ERROR</strong>: server fqdn is empty.'));
		if ($server_port<0) $error->add('nvalid_server_port',   __('<strong>ERROR</strong>: server port is invalid.'));
		return $error;
	}

	// 1: 認証成功, 2: 認証に失敗, 3: ユーザが存在しない, 負数: その他のエラー
	$result = tuis_check_auth($server_fqdn, $server_port, $lgname, $passwd, 0);
	if ($result!=1) {
		$error->add('login_error', __('<strong>ERROR</strong>: login failed.'));
		return $error;
	}

	//
	$user_id = null;
	$user = get_userdatabylogin($lgname);
	if (!$user) {
		$user_id = tuis_auth_create_user($lgname);
		if (is_a($user_id, 'WP_Error')) {
			$error->add('user_create_error', __('<strong>ERROR</strong>: creation of user failed. '.$user_id->get_error_message()));
			return $error;
		}
	}
	else {
		$user_id = $user->ID;
	}

remove_filter('authenticate', 'tuis_auth_authenticate', 1, 3);
	return new WP_User($user_id);
}



function  tuis_auth_create_user($lgname)
{
	$mailaddr = '';

	if (preg_match('/^[a-z]\d\d\d\d\d[a-z][a-z]$/', $lgname)) {
		// Student
		$username = substr($lgname, 0, 6);
		$mailaddr = $lgname.'@edu.tuis.ac.jp';
		$userrole = 'author';
	}
	else {
		// Teacher
		$username = $lgname;
		$mailaddr = $lgname.'@rsch.tuis.ac.jp';
		$userrole = 'author';
	}

	$userData = array(
		'user_pass'	 	=> microtime(),
		'user_login' 	=> $lgname,
		'user_nicename' => $username,
		'nickname'		=> $username,
		'user_email'	=> $mailaddr,
		'display_name'  => $username,
		'first_name'	=> '',
		'last_name'	 	=> '',
		'role'			=> $userrole
	);
				
	$result = wp_insert_user($userData); 

	return $result;
}



//
add_action('admin_menu',   'tuis_auth_admin_actions');
add_filter('authenticate', 'tuis_auth_authenticate', 1, 3);
//
register_activation_hook( __FILE__, 'tuis_auth_activation_hook' );

?>
