<?php
session_start();
require_once('../../vendor/autoload.php');

$v = new vOauth();
/*
 * Change values to what you need
 * scopes are set as constants
 */
$v->setClient("Your client here");
$v->setSecret("Your secret here");
$v->addScope(array(vOauth::SCOPE_PROFILE, vOauth::SCOPE_CONNECTIONENLID, vOauth::SCOPE_CONNECTIONGID));
$v->setRedirect("redirect URL here");
if (isset($_GET['logout'])) {
	unset($_SESSION['vACCESS_TOKEN']);
	unset($_SESSION['vREFRESH']);
}

if (isset($_GET['code'])) {
	if ($_GET['state'] === md5('stateGoesHere')) {
		$v->setCode(trim($_GET['code']));
		$_SESSION['vACCESS_TOKEN'] = $v->getToken("stateGoesHere");
		$_SESSION['vREFRESH'] = $v->getRefreshToken();
		//redirect to script after login
		header("Location: " . $v->redirect);
	} else {
		die("CSRF attack");
	}
//do something after login

} else if (isset($_SESSION['vACCESS_TOKEN'])) {
	//set token from session and use it to retrieve data

	$v->setToken($_SESSION['vACCESS_TOKEN']);
	try {
		$vInfo = $v->getVInfo();
		echo "You are logged into V. Welcome back " . $vInfo->{'agent'} . "<br><br>";
		var_dump($v->connection("39d8d4e351a0de8ce39ab3334f628628fac6e06a", $vInfo->{'enlid'}));

	} catch (Exception $e) {
		error_log($e->getMessage());
		echo $e->getMessage();
	}

} else {

	//if not logged in, create auth url
	echo $auth = $v->getAuthURL("stateGoesHere");
	//redirect to V Oauth login page
	header("Location: " . $auth);
}