<?php

	require_once(HelperPath.DS.'HTMLView.php');

	class LoginView {

		private $mainView;
		private static $loginErrorMessage = "Felaktigt användarnamn och/eller lösenord.";
		private static $emptyUsernameErrorMessage = "Användarnamn saknas.";
		private static $emptyPasswordErrorMessage = "Lösenord saknas.";
		private static $logOutSuccessMessage = "Du är nu utloggad.";
		private static $corruptCookieLogoutMessage = "Fel information i cookie.";
		private static $newUserSuccessMsg = 'Registrering av ny användare lyckades';
		private $regView;
		private $safe;
 
		function __construct () {

			$this->mainView = new HTMLView();
			$this->safe = new safe();
		}		

		public function getSafeInputPassword() {
			return $this->safe->create_hash($this->GetUsername());
		}
		public function getNewUserSuccessMsg() {
			return self::$newUserSuccessMsg;
		}

		public function getUserNameValue() {
			
			
		}

		public function GetLoginFormHTML ($message = '') {

			$responseMessages = '';

			if ($message != '') {
					
				$responseMessages .= '<p>' . $message . '</p>';
			}

			$loginHTML = 
			'<h2>Ej Inloggad</h2>' .




			'<form id="login" enctype="multipart/form-data" method="post" action="?login">' .
				'<fieldset>' .
					'<legend>Login - Skriv in användarnamn och lösenord</legend>' .
					$responseMessages .
					'<label for="username">Användarnamn : </label>' .
					'<input type="text" name="username" value="' . $_SESSION['LoginValues']['username'] . $this->getUserNameValue(). '" maxlength="30" id="username" /> ' .

					'<label for="password">Lösenord : </label>' .
					'<input type="password" name="password" maxlength="30" id="password" /> ' .

					'<label for="rememberMe">Håll mig inloggad :</label>
					<input id="rememberMe" type="checkbox" name="rememberMe">
					<input type="submit" name="submit" id="submit" value="Logga in" />
				</fieldset>
			</form>';

			$_SESSION['LoginValues']['username'] = "";

			return $loginHTML;			
		}

		public function RenderLoginForm ($errorMessage = '') {

			$loginHTML = $this->GetLoginFormHTML($errorMessage);
			echo $this->mainView->echoHTML($loginHTML);
		}

		public function RenderLogoutView ($isDefaultLogout = true) {

			$isDefaultLogout ? $this->RenderLoginForm(self::$logOutSuccessMessage)
							 : $this->RenderLoginForm(self::$corruptCookieLogoutMessage);
		}

		public function GetUsername () {

			if (isset($_POST['username'])) {
				
				return $_POST['username'];
			}
		}

		public function GetPassword () {

			if (isset($_POST['password'])) {
				
				return $_POST['password'];
			}
		}

		public function UserPressLoginButton () {

			return isset($_POST['submit']);
		}

		public function Validate () {

			if ($this->GetUsername() == null) {

				return self::$emptyUsernameErrorMessage;
			}

			else if ($this->GetPassword() == null) {

				$_SESSION['LoginValues']['username'] = $this->GetUsername();

				return self::$emptyPasswordErrorMessage;
			}

			return true;
		}

		public function AutoLoginIsChecked () {

			$isChecked = false;

			if (isset($_POST['rememberMe'])) {
				
				$isChecked = $_POST['rememberMe'];
			}

			return ($isChecked == 'true' || $isChecked == 'on') ? true : false;
		}

		public function GetLoginErrorMessage () {

			$_SESSION['LoginValues']['username'] = $this->GetUsername();

			return self::$loginErrorMessage;
		}

		public function userPressRegNewUser(){
			if (isset($_GET['registrera'])) {
				return true;
			}
			
		}
	}