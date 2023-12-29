<?php

if (!defined('MOODLE_INTERNAL')) {
    die('Direct access to this script is forbidden.');
}


require_once($CFG->libdir.'/authlib.php');



class auth_plugin_tuis extends auth_plugin_base {

    var $userfields = array(
        'lastname',
        'firstname',
        'email',
        'city',
        'country',
        'lang',
        'description',
        'url',
        'idnumber',
        'institution',
        'department',
        'phone1',
        'phone2',
        'address'
    );


    //function auth_plugin_tuis() {
    function __construct() {
        $this->authtype = 'tuis';
        $this->config = get_config('auth/tuis');
    }


    function user_login($username, $password) 
    {
        global $CFG, $DB;

        $host = $this->config->host;
        $port = $this->config->port;

        //if (!function_exists('check_auth')) {
        //    print_error('auth_tuisnotinstalled', 'auth_tuis');
        //    exit;
        //}
        error_reporting(0);

/*
        $username = escapeshellarg($username);
        $password = escapeshellarg($password);

        $ret = exec("/usr/local/bin/check_auth -h $host:$port -u $username -p $password -m -s");
        error_reporting($CFG->debug);

        if ($ret=='ok') {
            return true;
        }
        else if ($ret=='nu') {
            return false;
        } 
        else {
            return false;
        }
*/

        $ret = check_auth($host, $port, $username, $password, 0);
        error_reporting($CFG->debug);

        if ($ret==1) {
            // 成功したパスワードをローカルパスワードとする．
            if ($user = $DB->get_record('user', array('username'=>$username))) {
                if (!validate_internal_user_password($user, $password)) {
                    update_internal_user_password($user, $password);
                }
            }
            return true;
        } 
		else if ($ret==2) { 	// ユーザは存在するが，パスワードが一致しない
			// Register for TUIS
        	// $ret = check_auth($host, $port, 'xxxxx', $password, 0);
        	// if ($ret===1) return true;

            // ローカルパスワードを使用
            if ($user = $DB->get_record('user', array('username'=>$username))) {
                return validate_internal_user_password($user, $password);
            }
            return false;
		}
        else {
            return false;
        }
    }


/*
    function user_update_password($user, $newpassword) {
        $user = get_complete_user_data('id', $user->id);
        // This will also update the stored hash to the latest algorithm
        // if the existing hash is using an out-of-date algorithm (or the
        // legacy md5 algorithm).
        return update_internal_user_password($user, $newpassword);
    }
*/


    function user_exists($username) 
    {
        global $CFG;

        if (preg_match('/^[A-Za-z]\d\d\d\d\d$/', $username)) return true;
        if (preg_match('/^[A-Za-z]\d\d\d\d\d[A-Za-z][A-Za-z]$/', $username)) return true;

        $host = $this->config->host;
        $port = $this->config->port;

        if (!function_exists('tuis_check_auth')) {
            return false;
        }

        error_reporting(0);
        $ret = tuis_check_auth($host, $port, $username, "passwd", 0);
        error_reporting($CFG->debug);

        if ($ret==2 || $ret==1) {
            return true;
        } 
        else {
            return false;
        }
    }


    function get_userinfo($username) {
        $userinfo = array();


        if (preg_match('/^[a-z]\d\d\d\d\d[a-z][a-z]$/', $username)) {
        	$usermail = $username.'@edu.tuis.ac.jp';
            $username = substr($username, 0, 6);
        }
		else {
        	$usermail = $username.'@rsch.tuis.ac.jp';
		}
/*
        'lastname',
        'firstname',
        'email',
        'city',
        'country',
        'lang',
        'description',
        'url',
        'idnumber',
        'institution',
        'department',
        'phone1',
        'phone2',
        'address'
*/
        $userinfo['lastname'] = $username;
        $userinfo['firstname'] = $username;
        $userinfo['email'] = $usermail;
        $userinfo['city'] = 'Chiba';
        $userinfo['country'] = 'JP';

        return $userinfo;
    }


    // DB上のパスワードの変更禁止
    function prevent_local_passwords() {
        //return true;
        return false;
    }


    /**
     * Returns true if this authentication plugin is 'internal'.
     *
     * @return bool
     */
    function is_internal() {
        return false;
    }


    /**
     * Returns true if this authentication plugin can change the user's
     * password.
     * 
     * 変更用のページを表示するか？
     * 
     * @return bool
     */
    function can_change_password() {
        return false;
        //return true;
    }


    /**
     * Returns the URL for changing the user's pw, or false if the default can
     * be used.
     *
     * @return bool
     */
    function change_password_url() {
        return $this->config->changepasswordurl;
    }


    /**
     * Returns true if plugin allows resetting of internal password.
     *
     * @return bool
     */
    function can_reset_password() {
        return false;
    }


    /**
     * Prints a form for configuring this authentication plugin.
     *
     * This function is called from admin/auth.php, and outputs a full page with
     * a form for configuring this plugin.
     *
     * @param array $page An object containing all the data for this page.
     */
    function config_form($config, $err, $user_fields) {
        include "config.html";
    }


    /**
     * Processes and stores configuration data for this authentication plugin.
     */
    function process_config($config) {
        // set to defaults if undefined
        if (!isset ($config->host)) {
            $config->host = '127.0.0.1';
        }
        if (!isset ($config->port)) {
            $config->port = '9000';
        }
        if (!isset($config->changepasswordurl)) {
            $config->changepasswordurl = '';
        }

        // save settings
        set_config('host', $config->host, 'auth/tuis');
        set_config('port', $config->port, 'auth/tuis');
        set_config('changepasswordurl', $config->changepasswordurl, 'auth/tuis');

        return true;
    }


    function get_title() {
        return get_string("auth_tuisauthtitle", "auth_tuis");
    }


    function get_description() {
        return get_string("auth_tuisauthdescription", "auth_tuis");
    }
}
