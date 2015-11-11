<?php

	class CookieStorage {

		public $username;
		public $password;
		private static $usernameCookie = "username";
		private static $passwordCookie = "password";
		private static $cookieUsernameErrMsg = 'CookieUsername does not exist!';
		private static $cookiePasswordErrMsg = 'CookiePassword does not exist!';

		

		public function SaveUserCredentials ($username, $password, $cookieTimestamp) {

			
			
			setcookie(self::$usernameCookie, $username, $cookieTimestamp, "/");
			setcookie(self::$passwordCookie, $password, $cookieTimestamp, "/");
		}



		public function DeleteUserCredentials () {

			setcookie(self::$usernameCookie, "", 1, "/");
			setcookie(self::$passwordCookie, "", 1, "/");
		}

		public function RememberMe () {

			return isset($_COOKIE[self::$usernameCookie]);
		}

		public function GetCookieUsername () {

			if (isset($_COOKIE[self::$usernameCookie])) {
				
				return $_COOKIE[self::$usernameCookie];
			}
		

		}

		public function GetCookiePassword () {

			if (isset($_COOKIE[self::$passwordCookie])) {
				
				return $_COOKIE[self::$passwordCookie];
			}
			
		}		
	}