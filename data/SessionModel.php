<?php
	class SessionModel {

			private $isLoggedIn = false;
			private $userId;
			private $message;
			private static $sessionUserId = 'userId';
			private static $sessionUserHeadCategory = 'userdata';
			private static $sessionUsername = 'username';
			private static $sessionPassword = 'password';
			private static $securitySessionName = 'unique';
			private static $hashString = "sha256";
			private $userModel;

		function __construct () {
				$this->userModel = new UserModel();
			if (!isset($_SESSION[self::$sessionUserHeadCategory])) {
				
				$_SESSION[self::$sessionUserHeadCategory][self::$sessionUsername] = '';
			}
		}

		public function IsLoggedIn () {
			return isset($_SESSION[self::$sessionUsername]);
		}

		public function GetUserId () {
			return $this->username;
		}

		public function GetUsername () {
			return $_SESSION[self::$sessionUserHeadCategory][self::$sessionUsername];
		}

		public function LoginUser (User $user) {
			global $remote_ip;
			global $user_agent;
			
	    	$this->username = $_SESSION[self::$sessionUsername] = $user->getUsername();
			$_SESSION[self::$sessionUserHeadCategory][self::$sessionUsername] = $user->getUsername();
			$_SESSION[self::$securitySessionName] = hash(self::$hashString, $remote_ip . $user_agent);
			$this->isLoggedIn = true;
		}

		public function LogoutUser () {
			unset($_SESSION[self::$sessionUsername]);
			$this->isLoggedIn = false;
		}

		public function IsStolen ($validId) {
			return isset($_SESSION[self::$securitySessionName]) && $validId != $_SESSION[self::$securitySessionName];
		}
	}