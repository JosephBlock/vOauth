<?php

/**
 *
 * Licence: MIT License (MIT)
 * Copyright (c) 2017 Joseph Block
 *
 * This class is used to communicate and authenticate against V
 *
 * VERSION 1.7
 */
class vOauth
{
	//Data retrieval
	const URL_PROFILE = "api/v1/profile";
	const URL_GOOGLEDATA = "api/v1/googledata";
	const URL_EMAIL = "api/v1/email";
	const URL_TELEGRAM = "api/v1/telegram";
	const URL_OAUTH_USERINFO = "api/v1/userinfo";
	const URL_VTEAMS = "api/v1/teams";

	//Endpoints
	const ENDPOINT_AUTH = "authorize";
	const ENDPOINT_TOKEN = "token";
	const ENDPOINT_VERIFY = "verify";

	//Scopes
	const SCOPE_OPENID = "openid";
	const SCOPE_EMAIL = "email";
	const SCOPE_GOOGLEDATA = "googledata";
	const SCOPE_TELEGRAM = "telegram";
	const SCOPE_PROFILE = "profile";
	const SCOPE_TEAMS = "teams";

	//API Scopes
	const SCOPE_SEARCH = "search";
	const SCOPE_TRUSTENLID = "trustenlid";
	const SCOPE_TRUSTGID = "trustgid";
	const SCOPE_CONNECTIONENLID = "connectionenlid";
	const SCOPE_CONNECTIONGID = "connectiongid";
	const SCOPE_BULKINFOENLID = "bulkinfoenlid";
	const SCOPE_BULKINFOGID = "bulkinfogid";
	const SCOPE_BULKINFOTELEGRAMID = "bulkinfotelegramid";
	const SCOPE_QLOCATION = "qlocation";

	//API Endpoints
	const API_SEARCH = "api/v1/search";
	const API_TRUST = "api/v1/agent/{ID1}/trust";
	const API_CONNECTION = "api/v1/agent/{ID1}/{ID2}";
	const API_BULKINFO_ENLID = "api/v1/bulk/agent/info";
	const API_BULKINFO_GID = "api/v1/bulk/agent/info/gid";
	const API_BULKINFO_TELEGRAMID = "api/v1/bulk/agent/info/telegramid";
	const API_QLOCATION = "api/v1/agent/{ID1}/location";

	//Webhook Types
	const WEBHOOK_PROFILE = "profile";
	const WEBHOOK_EMAIL = "email";
	const WEBHOOK_GOOGLEDATA = "googledata";
	const WEBHOOK_TELEGRAM = "telegram";
	const WEBHOOK_LOCATION = "location";
	const WEBHOOK_TEAMS = "teams";

	//Webhook Scope
	const SCOPE_WEBHOOK = "sync";

	//Webhook Endpoints
	const WEBHOOK_ENDPOINT = "api/v2/callback/{TYPE}";

	//Testing Scope
	const TESTING_SCOPE = array(vOauth::SCOPE_OPENID,
		vOauth::SCOPE_EMAIL,
		vOauth::SCOPE_GOOGLEDATA,
		vOauth::SCOPE_TELEGRAM,
		vOauth::SCOPE_PROFILE,
		vOauth::SCOPE_TEAMS,
		vOauth::SCOPE_SEARCH,
		vOauth::SCOPE_TRUSTENLID,
		vOauth::SCOPE_TRUSTGID,
		vOauth::SCOPE_CONNECTIONENLID,
		vOauth::SCOPE_CONNECTIONGID,
		vOauth::SCOPE_BULKINFOENLID,
		vOauth::SCOPE_BULKINFOGID,
		vOauth::SCOPE_BULKINFOTELEGRAMID,
		vOauth::SCOPE_QLOCATION,
		vOauth::SCOPE_WEBHOOK);

	//variables
	public $client;
	public $secret;
	public $redirect;
	public $ch;
	public $root = "https://v.enl.one/oauth/";
	public $token;
	public $refreshToken;
	public $code;
	protected $scopes = array();

	/**
	 * vOauth constructor.
	 */
	public function __construct()
	{

		$this->ch = curl_init();
		curl_setopt($this->ch, CURLOPT_USERAGENT, 'vOauth API v1.5');
		curl_setopt($this->ch, CURLOPT_POST, true);
		curl_setopt($this->ch, CURLOPT_FOLLOWLOCATION, true);
		curl_setopt($this->ch, CURLOPT_HEADER, false);
		curl_setopt($this->ch, CURLOPT_RETURNTRANSFER, true);
		curl_setopt($this->ch, CURLOPT_CONNECTTIMEOUT, 30);
		curl_setopt($this->ch, CURLOPT_TIMEOUT, 600);

	}

	/**
	 * @param $state
	 *
	 * @return string
	 * @throws Exception
	 */
	public function getAuthURL($state)
	{
		if (!$this->redirect) throw new Exception('You must provide a redirect URL');
		if (!$this->scopes) throw new Exception('You must provide a OAuth scope');
		$scope = implode($this->scopes, "%20");


		$url = $this->root . vOauth::ENDPOINT_AUTH . "?type=web_server&client_id=" . $this->client . "&redirect_uri=" . $this->redirect . "&response_type=code&scope=" . $scope . "&state=" . md5($state);

		return $url;
	}

	/**
	 * sets the redirect
	 *
	 * @param $redirect
	 */
	public function setRedirect($redirect)
	{
		$this->redirect = $redirect;
	}

	/**
	 * destroys the curl session
	 */
	public function __destruct()
	{
		curl_close($this->ch);
	}

	/**
	 * @param $state
	 *
	 * @return mixed
	 * @throws Exception
	 */
	public function getToken($state)
	{
		if (!$this->code) throw new Exception("Required: use setCode before calling this function");

		$fields = array(
			'grant_type'    => 'authorization_code',
			'code'          => $this->code,
			'client_id'     => $this->client,
			'client_secret' => $this->secret,
			'redirect_uri'  => $this->redirect,
			'state'         => md5($state)
		);
		try {
			$result = $this->callPost(vOauth::ENDPOINT_TOKEN, $fields);

			$this->setToken($result->{'access_token'});
			$this->setRefreshToken($result->{'refresh_token'});

			return $this->token;
		} catch (Exception $e) {
			throw $e;
		}
	}

	/**
	 * @param mixed $token
	 */
	public function setToken($token)
	{
		$this->token = $token;
	}

	/**
	 * @param             $url
	 * @param array       $parms
	 * @param string|null $auth
	 * @param string      $fields_string
	 *
	 * @param string      $contentType
	 *
	 * @return mixed
	 * @throws Exception
	 */
	public function callPost($url, $parms, $auth = null, $fields_string = "", $contentType = "application/x-www-form-urlencoded")
	{
		if (!$this->client || !$this->secret) throw new Exception('You must provide a client and secret');
		if (!$this->redirect) throw new Exception('You must provide a redirect URL');
		$ch = $this->ch;
		foreach ($parms as $key => $value) {
			$fields_string .= $key . '=' . $value . '&';
		}
		$fields_string = rtrim($fields_string, '&');
		curl_setopt($ch, CURLOPT_URL, $this->root . $url);
		curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type: ' . $contentType, $auth));
		curl_setopt($ch, CURLOPT_POST, count($parms));
		curl_setopt($ch, CURLOPT_POSTFIELDS, $fields_string);
		$response_body = curl_exec($ch);
		if (curl_error($ch)) {
			throw new Exception("API call to $url failed: " . curl_error($ch));
		}
		$result = json_decode($response_body);
		if (isset($result->{'error'})) throw new Exception("Error: " . $result->{'error'} . " Message: " . $result->{'error_description'});
		if ($result === null) throw new Exception('We were unable to decode the JSON response from the API: ' . $response_body);

		return $result;
	}

	/**
	 * Json returned: enlid,vlevel,vpoints,quarantine,active,blacklisted,verified,agent,flagged
	 *
	 * @param array $field
	 *
	 * @return mixed
	 * @throws Exception
	 */
	public function getVInfo($field = array())
	{
		if (!$this->token) throw new Exception("No token");
		$fields = array();
		$fields = array_merge($fields, $field);
		try {
			$result = $this->callPost(vOauth::URL_PROFILE, $fields, "Authorization: Bearer " . $this->token);
			if ($result->{'status'} === "error") {
				throw new Exception($result->{'message'});
			} else {
				return $result->{'data'};
			}

		} catch (Exception $e) {
			throw $e;
		}
	}

	/**
	 * json returned:
	 * name,family_name,given_name,middle_name,nickname,preferred_username,profile,picture,website,gender,birthdate,zoneinfo,locale
	 * "updated_at":{date,timezone_type,timezone }
	 *
	 *
	 * @param array $field
	 *
	 * @return mixed
	 * @throws Exception
	 */
	public function getOpenIDProfile($field = array())
	{
		if (!$this->token) throw new Exception("No token");
		$fields = array();
		$fields = array_merge($fields, $field);
		try {
			$result = $this->callPost(vOauth::URL_OAUTH_USERINFO, $fields, "Authorization: Bearer " . $this->token);

			if ($result->{'status'} === "error") {
				throw new Exception($result->{'message'});
			} else {
				json_encode($result);

				return $result;
			}


		} catch (Exception $e) {
			throw $e;
		}
	}

	/**
	 * json returned: gid,forename,lastname,User,imageurl
	 *
	 * @param array $field
	 *
	 * @return mixed
	 * @throws Exception
	 */
	public function getGoogleData($field = array())
	{
		if (!$this->token) throw new Exception("No token");
		$fields = array();
		$fields = array_merge($fields, $field);

		try {
			$result = $this->callPost(vOauth::URL_GOOGLEDATA, $fields, "Authorization: Bearer " . $this->token);

			if ($result->{'status'} === "error") {
				throw new Exception($result->{'message'});
			} else {
				return $result->{'data'};
			}
		} catch (Exception $e) {
			throw $e;
		}
	}

	/**
	 * json returned: email
	 *
	 * @param array $field
	 *
	 * @return mixed
	 * @throws Exception
	 */
	public function getEmail($field = array())
	{
		if (!$this->token) throw new Exception("No token");
		$fields = array();
		$fields = array_merge($fields, $field);
		try {
			$result = $this->callPost(vOauth::URL_EMAIL, $fields, "Authorization: Bearer " . $this->token);
			if ($result->{'status'} === "error") {
				throw new Exception($result->{'message'});
			} else {
				return $result->{'data'};
			}
		} catch (Exception $e) {
			throw $e;
		}
	}

	/**
	 * json returned: telegram
	 *
	 * @param array $field
	 *
	 * @return mixed
	 * @throws Exception
	 */
	public function getTelegram($field = array())
	{
		if (!$this->token) throw new Exception("No token");
		$fields = array();
		$fields = array_merge($fields, $field);
		try {
			$result = $this->callPost(vOauth::URL_TELEGRAM, $fields, "Authorization: Bearer " . $this->token);
			if ($result->{'status'} === "error") {
				throw new Exception($result->{'message'});
			} else {
				return $result->{'data'};
			}
		} catch (Exception $e) {
			throw $e;
		}

	}

	/**
	 * returned json array:
	 * {
	 * "teamid": 1,
	 * "team":   "My Team 1",
	 * "role":   "Operator",
	 * "admin":  true
	 * },
	 * {
	 * "teamid": 1337,
	 * "team":   "My Other Team",
	 * "role":   "Linker",
	 * "admin":  false
	 * }
	 *
	 * @param array $field
	 *
	 * @return mixed
	 * @throws Exception
	 */
	public function getVTeams($field = array())
	{
		if (!$this->token) throw new Exception("No token");
		$fields = array();
		$fields = array_merge($fields, $field);
		try {
			$result = $this->callPost(vOauth::URL_VTEAMS, $fields, "Authorization: Bearer " . $this->token);
			if ($result->{'status'} === "error") {
				throw new Exception($result->{'message'});
			} else {
				return $result->{'data'};
			}
		} catch (Exception $e) {
			throw $e;
		}
	}

	/**
	 * returns json array:
	 * role, admin, agent, level, enlid, gid, vlevel, vpoints, quarantine, active, blacklisted, verified, telegramid,
	 * telegram, email, lat, lon, distance
	 *
	 * @param       $teamID
	 * @param array $field
	 *
	 * @return mixed
	 * @throws Exception
	 */
	public function getVTeamInfo($teamID, $field = array())
	{
		if (!$this->token) throw new Exception("No token");
		$fields = array();
		$fields = array_merge($fields, $field);
		try {
			$result = $this->callPost(vOauth::URL_VTEAMS . "/" . $teamID, $fields, "Authorization: Bearer " . $this->token);
			if ($result->{'status'} === "error") {
				throw new Exception($result->{'message'});
			} else {
				return $result->{'data'};
			}
		} catch (Exception $e) {
			throw $e;
		}
	}

	/**
	 * @param       $search
	 * @param array $field
	 *
	 * @return mixed
	 * @throws Exception
	 */
	public function search($search, $field = array())
	{
		if ($search instanceof Search) {
			if (!$this->token) {
				throw new Exception("No token");
			}
			echo $search;
			if (empty($search->getQuery()) && (empty($search->getLat()) && empty($search->getLon()))) {
				throw new Exception("No query or Lat/Lon set");
			}

			$fields = array();
			$fields = array_merge($fields, $field);
			try {

				$result = $this->callPost(vOauth::API_SEARCH . "?" . $search, $fields, "Authorization: Bearer " . $this->token);

				if ($result->{'status'} === "error") {
					throw new Exception($result->{'message'});
				} else {
					return $result->{'data'};
				}
			} catch (Exception $e) {
				throw $e;
			}
		} else {
			throw new Exception("Must be a Search object");
		}
	}

	/**
	 * @param       $agent1
	 * @param array $field
	 *
	 * @return mixed
	 * @throws Exception
	 */
	public
	function trust($agent1, $field = array())
	{
		if (!$this->token) throw new Exception("No token");
		$fields = array();
		$fields = array_merge($fields, $field);
		try {
			$url = str_replace("{ID1}", $agent1, vOauth::API_TRUST);

			$result = $this->callPost($url, $fields, "Authorization: Bearer " . $this->token);
			var_dump($url);
			if ($result->{'status'} === "error") {
				throw new Exception($result->{'message'});
			} else {
				return $result->{'data'};
			}
		} catch (Exception $e) {
			throw $e;
		}
	}

	/**
	 * @param       $agent1
	 * @param       $agent2
	 * @param array $field
	 *
	 * @return mixed
	 * @throws Exception
	 */
	public
	function connection($agent1, $agent2, $field = array())
	{
		if (!$this->token) throw new Exception("No token");
		$fields = array();
		$fields = array_merge($fields, $field);
		try {
			$url = str_replace("{ID1}", $agent1, vOauth::API_CONNECTION);
			$url = str_replace("{ID2}", $agent2, $url);
			$result = $this->callPost($url, $fields, "Authorization: Bearer " . $this->token);

			if ($result->{'status'} === "error") {
				throw new Exception($result->{'message'});
			} else {
				return $result->{'data'};
			}
		} catch (Exception $e) {
			throw $e;
		}
	}

	/**
	 * @param       $bulk
	 * @param array $field
	 *
	 * @return mixed
	 * @throws Exception
	 */
	public
	function bulkinfo_enlid($bulk, $field = array())
	{
		if (!$this->token) throw new Exception("No token");
		$fields = array();
		$fields = array_merge($fields, $field);
		$bulk = implode('","', $bulk);
		$bulk = '["' . $bulk . '"]';
		echo $bulk;
		try {

			$result = $this->callPost(vOauth::API_BULKINFO_ENLID, $fields, "Authorization: Bearer " . $this->token, $bulk, "application/json");

			if ($result->{'status'} === "error") {
				throw new Exception($result->{'message'});
			} else {
				return $result->{'data'};
			}
		} catch (Exception $e) {
			throw $e;
		}
	}

	/**
	 * @param       $bulk
	 * @param array $field
	 *
	 * @return mixed
	 * @throws Exception
	 */
	public
	function bulkinfo_gid($bulk, $field = array())
	{
		if (!$this->token) throw new Exception("No token");
		$fields = array();
		$fields = array_merge($fields, $field);
		$bulk = implode('","', $bulk);
		$bulk = '["' . $bulk . '"]';
		try {

			$result = $this->callPost(vOauth::API_BULKINFO_GID, $fields, "Authorization: Bearer " . $this->token, $bulk, "application/json");

			if ($result->{'status'} === "error") {
				throw new Exception($result->{'message'});
			} else {
				return $result->{'data'};
			}
		} catch (Exception $e) {
			throw $e;
		}
	}

	/**
	 * @param       $bulk
	 * @param array $field
	 *
	 * @return mixed
	 * @throws Exception
	 */
	public
	function bulkinfo_telegramid($bulk, $field = array())
	{
		if (!$this->token) throw new Exception("No token");
		$fields = array();
		$fields = array_merge($fields, $field);
		$bulk = implode(",", $bulk);
		$bulk = "[" . $bulk . "]";
		try {

			$result = $this->callPost(vOauth::API_BULKINFO_TELEGRAMID, $fields, "Authorization: Bearer " . $this->token, $bulk);

			if ($result->{'status'} === "error") {
				throw new Exception($result->{'message'});
			} else {
				return $result->{'data'};
			}
		} catch (Exception $e) {
			throw $e;
		}
	}

	/**
	 * @param       $agent1
	 * @param array $field
	 *
	 * @return mixed
	 * @throws Exception
	 */
	public function location($agent1, $field = array())
	{
		if (!$this->token) throw new Exception("No token");
		$fields = array();
		$fields = array_merge($fields, $field);
		try {
			$url = str_replace("{ID1}", $agent1, vOauth::API_QLOCATION);
			$result = $this->callPost($url, $fields, "Authorization: Bearer " . $this->token);

			if ($result->{'status'} === "error") {
				throw new Exception($result->{'message'});
			} else {
				return $result->{'data'};
			}
		} catch (Exception $e) {
			throw $e;
		}
	}

	public function set_webhook($type, $webhook_url, $field = array())
	{
		if (!$this->token) throw new Exception("No token");
		$fields = array();
		$fields = array_merge($fields, $field);
		try {
			$url = str_replace("{TYPE}", $type, vOauth::WEBHOOK_ENDPOINT);
			$url = $url . "?url=" . $webhook_url;
			$result = $this->callPost($url, $fields, "Authorization: Bearer " . $this->token);

			if ($result->{'status'} === "error") {
				throw new Exception($result->{'message'});
			} else {
				return true;
			}
		} catch (Exception $e) {
			throw $e;
		}
	}

	public function get_webhook($type)
	{
		if (!$this->token) throw new Exception("No token");
		try {
			$url = str_replace("{TYPE}", $type, vOauth::WEBHOOK_ENDPOINT);
			$result = $this->callGet($url, "Authorization: Bearer " . $this->token);
			if ($result->{'status'} === "error") {
				throw new Exception($result->{'message'});
			} else {
				return true;
			}
		} catch (Exception $e) {
			throw $e;
		}
	}

	public function callGet($url, $auth = null, $contentType = "application/x-www-form-urlencoded")
	{
		if (!$this->client || !$this->secret) throw new Exception('You must provide a client and secret');
		if (!$this->redirect) throw new Exception('You must provide a redirect URL');
		$ch = $this->ch;
		curl_setopt($ch, CURLOPT_URL, $this->root . $url);
		curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type: ' . $contentType, $auth));
		curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "DELETE");
		$response_body = curl_exec($ch);
		if (curl_error($ch)) {
			throw new Exception("API call to $url failed: " . curl_error($ch));
		}
		$result = json_decode($response_body);
		if (isset($result->{'error'})) throw new Exception("Error: " . $result->{'error'} . " Message: " . $result->{'error_description'});
		if ($result === null) throw new Exception('We were unable to decode the JSON response from the API: ' . $response_body);

		return $result;
	}

	public function delete_webhook($type)
	{
		if (!$this->token) throw new Exception("No token");
		try {
			$url = str_replace("{TYPE}", $type, vOauth::WEBHOOK_ENDPOINT);
			$result = $this->callDelete($url, "Authorization: Bearer " . $this->token);
			if ($result->{'status'} === "error") {
				throw new Exception($result->{'message'});
			} else {
				return true;
			}
		} catch (Exception $e) {
			throw $e;
		}
	}

	public function callDelete($url, $auth = null, $contentType = "application/x-www-form-urlencoded")
	{
		if (!$this->client || !$this->secret) throw new Exception('You must provide a client and secret');
		if (!$this->redirect) throw new Exception('You must provide a redirect URL');
		$ch = $this->ch;
		curl_setopt($ch, CURLOPT_URL, $this->root . $url);
		curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type: ' . $contentType, $auth));
		curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "DELETE");

		$response_body = curl_exec($ch);
		if (curl_error($ch)) {
			throw new Exception("API call to $url failed: " . curl_error($ch));
		}
		$result = json_decode($response_body);
		if (isset($result->{'error'})) throw new Exception("Error: " . $result->{'error'} . " Message: " . $result->{'error_description'});
		if ($result === null) throw new Exception('We were unable to decode the JSON response from the API: ' . $response_body);

		return $result;
	}

	/**
	 * @param       $refreshToken
	 *
	 * @param       $state
	 *
	 * @param array $field
	 *
	 * @return mixed
	 * @throws Exception
	 */
	public
	function getNewToken($refreshToken, $state, $field = array())
	{
		$fields = array(
			'grant_type'    => 'refresh_token',
			'refresh_token' => $refreshToken,
			'client_id'     => $this->client,
			'client_secret' => $this->secret,
			"state"         => md5($state)
		);
		$fields = array_merge($fields, $field);
		$result = $this->callPost(vOauth::ENDPOINT_TOKEN, $fields);
		$this->setToken($result->{'access_token'});
		if (isset($result->{'refresh_token'})) {
			$this->setRefreshToken($result->{'refresh_token'});
		}

		return $this->token;
	}

	/**
	 * @param $scopes
	 */
	public
	function addScope($scopes)
	{
		if (is_string($scopes) && !in_array($scopes, $this->scopes)) {
			$this->scopes[] = $scopes;
		} else if (is_array($scopes)) {
			foreach ($scopes as $scope) {
				$this->addScope(trim($scope));
			}
		}
	}

	/**
	 * @return mixed
	 */
	public
	function getRefreshToken()
	{
		return $this->refreshToken;
	}

	/**
	 * @param mixed $refreshToken
	 */
	public
	function setRefreshToken($refreshToken)
	{
		$this->refreshToken = $refreshToken;
	}

	/**
	 * @param mixed $code
	 */
	public
	function setCode($code)
	{
		$this->code = $code;
	}

	/**
	 * @param mixed $client
	 */
	public
	function setClient($client)
	{
		$this->client = $client;
	}

	/**
	 * @param mixed $secret
	 */
	public
	function setSecret($secret)
	{
		$this->secret = $secret;
	}

}

class Search
{

	private $search = array("query"       => null,
	                        "soundex"     => false,
	                        "minlevel"    => 1,
	                        "maxlevel"    => 16,
	                        "interest"    => "any",
	                        "inactive"    => false,
	                        "lat"         => null,
	                        "lon"         => null,
	                        "range"       => null,
	                        "extCircles"  => false,
	                        "tlMin"       => null,
	                        "tlMax"       => null,
	                        "tpMin"       => null,
	                        "tpMax"       => null,
	                        "verified"    => null,
	                        "flagged"     => null,
	                        "quarantined" => null,
	                        "blacklisted" => null,
	                        "hibernated"  => null,
	                        "agent"       => null,
	                        "fullname"    => null,
	                        "telegram"    => null,
	                        "telegramId"  => null);

	/**
	 * Optionally use associated array to fill in values
	 *
	 * Takes associated array where keys are the Parameter and value is the value to be set.
	 * Defaults and parameters are detailed on https://v.enl.one/apikey
	 *
	 * @param array $input
	 */
	function __construct($input = null)
	{
		set_error_handler(function ($errno, $errstr, $errfile, $errline) { throw new ErrorException($errstr, $errno, 0, $errfile, $errline); });
		if (is_array($input)) {
			foreach ($input as $key => $val) {
				try {
					$func = "set" . $key;
					$this->$func($val);
				} catch (Exception $e) {

				}
			}
		}
	}

	/**
	 * Returns query string for Search object
	 *
	 * @return string
	 */
	function __toString()
	{
		return http_build_query($this->search);

	}

	/**
	 * @return mixed
	 */
	public function getQuery()
	{
		return $this->search['query'];
	}

	/**
	 * @param mixed $query
	 */
	public function setQuery($query)
	{
		$this->search['query'] = $query;
	}

	/**
	 * @return bool
	 */
	public function isSoundex()
	{
		return $this->search['soundex'];
	}

	/**
	 * @param bool $soundex
	 */
	public function setSoundex($soundex)
	{
		$this->search['soundex'] = $soundex;
	}

	/**
	 * @return int
	 */
	public function getMinlevel()
	{
		return $this->search['minlevel'];
	}

	/**
	 * @param int $minlevel
	 */
	public function setMinlevel($minlevel)
	{
		$this->search['minlevel'] = $minlevel;
	}

	/**
	 * @return int
	 */
	public function getMaxlevel()
	{
		return $this->search['maxlevel'];
	}

	/**
	 * @param int $maxlevel
	 */
	public function setMaxlevel($maxlevel)
	{
		$this->search['maxlevel'] = $maxlevel;
	}

	/**
	 * @return string
	 */
	public function getInterest()
	{
		return $this->search['interest'];
	}

	/**
	 * @param string $interest
	 */
	public function setInterest($interest)
	{
		$this->search['interest'] = $interest;
	}

	/**
	 * @return bool
	 */
	public function isInactive()
	{
		return $this->search['inactive'];
	}

	/**
	 * @param bool $inactive
	 */
	public function setInactive($inactive)
	{
		$this->search['inactive'] = $inactive;
	}

	/**
	 * @return mixed
	 */
	public function getLat()
	{
		return $this->search['lat'];
	}

	/**
	 * @param mixed $lat
	 */
	public function setLat($lat)
	{
		$this->search['lat'] = $lat;
	}

	/**
	 * @return mixed
	 */
	public function getLon()
	{
		return $this->search['lon'];
	}

	/**
	 * @param mixed $lon
	 */
	public function setLon($lon)
	{
		$this->search['lon'] = $lon;
	}

	/**
	 * @return mixed
	 */
	public function getRange()
	{
		return $this->search['range'];
	}

	/**
	 * @param mixed $range
	 */
	public function setRange($range)
	{
		$this->search['range'] = $range;
	}

	/**
	 * @return bool
	 */
	public function isExtCircles()
	{
		return $this->search['extCircles'];
	}

	/**
	 * @param bool $extCircles
	 */
	public function setExtCircles($extCircles)
	{
		$this->search['extCircles'] = $extCircles;
	}

	/**
	 * @return mixed
	 */
	public function getTlMin()
	{
		return $this->search['tlMin'];
	}

	/**
	 * @param mixed $tlMin
	 */
	public function setTlMin($tlMin)
	{
		$this->search['tlMin'] = $tlMin;
	}

	/**
	 * @return mixed
	 */
	public function getTlMax()
	{
		return $this->search['tlMax'];
	}

	/**
	 * @param mixed $tlMax
	 */
	public function setTlMax($tlMax)
	{
		$this->search['tlMax'] = $tlMax;
	}

	/**
	 * @return mixed
	 */
	public function getTpMin()
	{
		return $this->search['tpMin'];
	}

	/**
	 * @param mixed $tpMin
	 */
	public function setTpMin($tpMin)
	{
		$this->search['tpMin'] = $tpMin;
	}

	/**
	 * @return mixed
	 */
	public function getTpMax()
	{
		return $this->search['tpMax'];
	}

	/**
	 * @param mixed $tpMax
	 */
	public function setTpMax($tpMax)
	{
		$this->search['tpMax'] = $tpMax;
	}

	/**
	 * @return mixed
	 */
	public function getVerified()
	{
		return $this->search['verified'];
	}

	/**
	 * @param mixed $verified
	 */
	public function setVerified($verified)
	{
		$this->search['verified'] = $verified;
	}

	/**
	 * @return mixed
	 */
	public function getFlagged()
	{
		return $this->search['flagged'];
	}

	/**
	 * @param mixed $flagged
	 */
	public function setFlagged($flagged)
	{
		$this->search['flagged'] = $flagged;
	}

	/**
	 * @return mixed
	 */
	public function getQuarantined()
	{
		return $this->search['quarantined'];
	}

	/**
	 * @param mixed $quarantined
	 */
	public function setQuarantined($quarantined)
	{
		$this->search['quarantined'] = $quarantined;
	}

	/**
	 * @return mixed
	 */
	public function getBlacklisted()
	{
		return $this->search['blacklisted'];
	}

	/**
	 * @param mixed $blacklisted
	 */
	public function setBlacklisted($blacklisted)
	{
		$this->search['blacklisted'] = $blacklisted;
	}

	/**
	 * @return mixed
	 */
	public function getHibernated()
	{
		return $this->search['hibernated'];
	}

	/**
	 * @param mixed $hibernated
	 */
	public function setHibernated($hibernated)
	{
		$this->search['hibernated'] = $hibernated;
	}

	/**
	 * @return mixed
	 */
	public function getAgent()
	{
		return $this->search['agent'];
	}

	/**
	 * @param mixed $agent
	 */
	public function setAgent($agent)
	{
		$this->search['agent'] = $agent;
	}

	/**
	 * @return mixed
	 */
	public function getFullname()
	{
		return $this->search['fullname'];
	}

	/**
	 * @param mixed $fullname
	 */
	public function setFullname($fullname)
	{
		$this->search['fullname'] = $fullname;
	}

	/**
	 * @return mixed
	 */
	public function getTelegram()
	{
		return $this->search['telegram'];
	}

	/**
	 * @param mixed $telegram
	 */
	public function setTelegram($telegram)
	{
		$this->search['telegram'] = $telegram;
	}

	/**
	 * @return mixed
	 */
	public function getTelegramId()
	{
		return $this->search['telegramId'];
	}

	/**
	 * @param mixed $telegramId
	 */
	public function setTelegramId($telegramId)
	{
		$this->search['telegramId'] = $telegramId;
	}
}