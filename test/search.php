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
$v->addScope(array(vOauth::SCOPE_PROFILE, vOauth::SCOPE_SEARCH));
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
		echo "You are logged into V. Welcome back " . $vInfo->{'agent'} . "<br>";
		//create a Search object
		$search = new Search();
		$search->setQuery("disastertrident");
		var_dump($v->search($search));
		//or creating an associated array with the values
		$search2 = new Search(array("query" => "disastertrident"));
		var_dump($v->search($search2));

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

