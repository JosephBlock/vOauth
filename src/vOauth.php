<?php

/**
 *
 * Licence: MIT License (MIT)
 * Copyright (c) 2016 Joseph Block
 *
 * This class is used to communicate and authenticate against V
 *
 */
class vOauth
{
	//Data retrieval
	const URL_PROFILE = "api/v1/profile";
	const URL_GOOGLEDATA = "api/v1/googledata";
	const URL_EMAIL = "api/v1/email";
	const URL_TELEGRAM = "api/v1/telegram";
	const URL_OAUTH_USERINFO = "api/v1/userinfo";

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
	 * vOAUTH constructor.
	 */
	public function __construct()
	{

		$this->ch = curl_init();
		curl_setopt($this->ch, CURLOPT_USERAGENT, 'VOAuth API v1');
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


		$url = $this->root . vOAUTH::ENDPOINT_AUTH . "?type=web_server&client_id=" . $this->client . "&redirect_uri=" . $this->redirect . "&response_type=code&scope=" . $scope . "&state=" . md5($state);
		return $url;
	}

	/**
	 * @param $redirect
	 */
	public function setRedirect($redirect)
	{
		$this->redirect = $redirect;
	}

	/**
	 *
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
			$result = $this->callPost(vOAUTH::ENDPOINT_TOKEN, $fields);

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
	 * @param      $url
	 * @param      $parms
	 * @param null $auth
	 *
	 * @return mixed
	 * @throws Exception
	 */
	public function callPost($url, $parms, $auth = null)
	{
		if (!$this->client || !$this->secret) throw new Exception('You must provide a client and secret');
		if (!$this->redirect) throw new Exception('You must provide a redirect URL');
		$ch = $this->ch;
		$fields_string = '';
		foreach ($parms as $key => $value) {
			$fields_string .= $key . '=' . $value . '&';
		}
		$fields_string = rtrim($fields_string, '&');
		curl_setopt($ch, CURLOPT_URL, $this->root . $url);
		curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type: application/x-www-form-urlencoded', $auth));
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
	 * Json returned: enlid,vlevel,vpoints,quarantine,active,blacklisted,verified,agent
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
			$result = $this->callPost(vOAUTH::URL_PROFILE, $fields, "Authorization: Bearer " . $this->token);
			if ($result->{'status'} === "error") {
				throw new Exception("Must re-auth");
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
			$result = $this->callPost(vOAUTH::URL_OAUTH_USERINFO, $fields, "Authorization: Bearer " . $this->token);

			if ($result->{'status'} === "error") {
				throw new Exception("Must re-auth");
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
			$result = $this->callPost(vOAUTH::URL_GOOGLEDATA, $fields, "Authorization: Bearer " . $this->token);

			if ($result->{'status'} === "error") {
				throw new Exception("Must re-auth");
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
			$result = $this->callPost(vOAUTH::URL_EMAIL, $fields, "Authorization: Bearer " . $this->token);
			if ($result->{'status'} === "error") {
				throw new Exception("Must re-auth");
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
			$result = $this->callPost(vOAUTH::URL_TELEGRAM, $fields, "Authorization: Bearer " . $this->token);
			if ($result->{'status'} === "error") {
				throw new Exception("Must re-auth");
			} else {
				return $result->{'data'};
			}
		} catch (Exception $e) {
			throw $e;
		}

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
	public function getNewToken($refreshToken, $state, $field = array())
	{
		$fields = array(
			'grant_type'    => 'refresh_token',
			'refresh_token' => $refreshToken,
			'client_id'     => $this->client,
			'client_secret' => $this->secret,
			"state"         => md5($state)
		);
		$fields = array_merge($fields, $field);
		$result = $this->callPost(vOAUTH::ENDPOINT_TOKEN, $fields);
		$this->setToken($result->{'access_token'});
		if (isset($result->{'refresh_token'})) {
			$this->setRefreshToken($result->{'refresh_token'});
		}
		return $this->token;
	}

	/**
	 * @param $scopes
	 */
	public function addScope($scopes)
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
	public function getRefreshToken()
	{
		return $this->refreshToken;
	}

	/**
	 * @param mixed $refreshToken
	 */
	public function setRefreshToken($refreshToken)
	{
		$this->refreshToken = $refreshToken;
	}

	/**
	 * @param mixed $code
	 */
	public function setCode($code)
	{
		$this->code = $code;
	}

	/**
	 * @param mixed $client
	 */
	public function setClient($client)
	{
		$this->client = $client;
	}

	/**
	 * @param mixed $secret
	 */
	public function setSecret($secret)
	{
		$this->secret = $secret;
	}

}