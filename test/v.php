<?php
session_start();
require_once('../../vendor/autoload.php');

$v=new vOauth();
/*
 * Change values to what you need
 * scopes are set as constants
 */
$v->setClient("Your client here");
$v->setSecret("Your secret here");
$v->addScope(array("Add scopes here"));
$v->setRedirect("redirect URL here");
if(isset($_GET['logout'])){
	unset($_SESSION['vACCESS_TOKEN']);
	unset($_SESSION['vREFRESH']);
}

if(isset($_GET['code'])){
	if ($_GET['state'] === md5('stateGoesHere')) {
	$v->setCode(trim($_GET['code']));
		$_SESSION['vACCESS_TOKEN'] = $v->getToken("stateGoesHere");
		$_SESSION['vREFRESH'] = $v->getRefreshToken();
	} else {
		die("CSRF attack");
	}
//do something after login

}
elseif(isset($_SESSION['vACCESS_TOKEN'])){
	//set token from session and use it to retrieve data

	$v->setToken($_SESSION['vACCESS_TOKEN']);
	try {
		$vInfo = $v->getVInfo();
		echo "you are logged into v. Welcome back ". $vInfo->{'agent'};

	} catch (Exception $e) {
		echo $e->getMessage();
	}

}else{

	//if not logged in, create auth url
	echo $auth = $v->getAuthURL("stateGoesHere");
}

