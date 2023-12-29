<?php

//
// Fumi.Iseki  '09 12/20 
//


if (!defined('XOOPS_ROOT_PATH')) die();



class  User_TuisAuth extends XCube_ActionFilter
{

	function preBlockFilter()
	{
		$root =& XCube_Root::getSingleton();
		$root->mDelegateManager->add("Site.CheckLogin", "User_TuisAuth::tuisCheckLogin", XCUBE_DELEGATE_PRIORITY_FIRST);
		$root->mDelegateManager->add("Legacypage.Register.Access", "User_TuisAuth::tuisCheckUser", XCUBE_DELEGATE_PRIORITY_FIRST);
	}



	function postFilter()
	{
	}	



	function tuisCheckUser()
	{
		$root =& XCube_Root::getSingleton();
		$xoopsUser =& $root->mContext->mXoopsUser;
   
		if (is_object($xoopsUser)) {
			$root->mController->executeForward(XOOPS_URL);
		}
   
		$userid = $root->mContext->mRequest->getRequest('uname');

		if ($userid!=null) {
			if (!defined('XOOPS_TUIS_AUTH_SERVER') or !defined('XOOPS_TUIS_AUTH_PORT')) {
				$root->mController->executeRedirect(XOOPS_URL, 3, "XOOPS_TUIS_AUTH_* is not defined.");
			}

			dl("php_tuis_auth.so");
			if (!function_exists('tuis_check_auth')) {
				$root->mController->executeRedirect(XOOPS_URL, 3, "php_tuis_asuth.so is not found.");
			}

			$result = tuis_check_auth(XOOPS_TUIS_AUTH_SERVER, XOOPS_TUIS_AUTH_PORT, $userid, "passwd", 0);

			if ($result==1 or $result==2) {
				$root->mController->executeRedirect(XOOPS_URL.'/register.php', 3, "User is already exist in External.");
			}
		}

		return;
	}


	function tuisCheckLogin(&$xoopsUser)
	{
		if (is_object($xoopsUser)) {
			return;				// 他の関数で認証済み
		}


		$root   =& XCube_Root::getSingleton();

		if (!defined('XOOPS_TUIS_AUTH_SERVER') or !defined('XOOPS_TUIS_AUTH_PORT')) {
			$root->mController->executeRedirect(XOOPS_URL, 3, "XOOPS_TUIS_AUTH_* is not defined.");
		}

		dl("php_tuis_auth.so");
		if (!function_exists('tuis_check_auth')) {
			$root->mController->executeRedirect(XOOPS_URL, 3, "php_tuis_asuth.so is not found.");
		}


		$userid = strtolower(xoops_getrequest('uname'));
		$passwd = xoops_getrequest('pass');
		$result = tuis_check_auth(XOOPS_TUIS_AUTH_SERVER, XOOPS_TUIS_AUTH_PORT, $userid, $passwd, 0);

		if ($result==1) {		// 外部ユーザ
			$maddr  = User_TuisAuth::makeMailAddr($userid);
			$userid = User_TuisAuth::changeUserID($userid);
		}
		elseif ($result==2){  	// 外部ユーザ パスワード間違い
			$root->mController->executeRedirect(XOOPS_URL, 3, "External User: Login Failed.");
		}
		else {
			return;
		}


		$root->mLanguageManager->loadModuleMessageCatalog('user');
		$userHandler =& xoops_getmodulehandler('users', 'user');
		
		$criteria =& new CriteriaCompo();
		$criteria->add(new Criteria('uname', $userid));
		$userArr =& $userHandler->getObjects($criteria);


		// ユーザ登録
		if (count($userArr)==0) {
			User_TuisAuth::setNewUser($root, $userid, $passwd, $maddr);
			$userArr =& $userHandler->getObjects($criteria);
			if (count($userArr)==0) return;
			User_TuisAuth::setUserGroups($userArr[0]->get('uid'));
		}

		if ($userArr[0]->get('level')==0) return;
		

		$handler =& xoops_gethandler('user');
		$user =& $handler->get($userArr[0]->get('uid'));
		$xoopsUser = $user;
	
		$root->mSession->regenerate();
		$_SESSION = array();
		$_SESSION['xoopsUserId'] = $xoopsUser->get('uid');
		$_SESSION['xoopsUserGroups'] = $xoopsUser->getGroups();

		return;
	}



	function setNewUser($root, $userid, $passwd, $maddr='')
	{
		$mHandler =& xoops_gethandler('member');
		$newUser  =& $mHandler->createUser();

	   	$newUser->set('name',  $userid, true);
	   	$newUser->set('uname', $userid, true);
	   	$newUser->set('pass',  md5($passwd), true);
	   	$newUser->set('email', $maddr, true);
	   	$newUser->set('timezone_offset', 9, true);
	   	$newUser->set('user_regdate', time(), true);
		$newUser->set('user_mailok', 0, true);

	   	$newUser->set('uorder', $root->mContext->getXoopsConfig('com_order'), true);
	   	$newUser->set('umode',  $root->mContext->getXoopsConfig('com_mode'),  true);
	   	$newUser->set('level', 1, true);

	   	$mHandler->insertUser($newUser);

		return;
	}



	//
	// for Localize
	//
	function changeUserID($userid)
	{
		if (preg_match('/^[a-z]\d\d\d\d\d[a-z][a-z]$/', $userid)) {
			$userid = substr($userid, 0, 6);
		}
		return $userid;
	}


	function makeMailAddr($userid)
	{
		return $userid.'@edu.tuis.ac.jp';
	}


	function setUserGroups($uid)
	{
		$mHandler =& xoops_gethandler('member');

		$mHandler->addUserToGroup(2, $uid);
		$mHandler->addUserToGroup(7, $uid);

		return;
	}
}
?>
