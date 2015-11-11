<?php

	require_once(HelperPath.DS.'SessionModel.php');
	require_once(ModelPath.DS.'UserModel.php');
	require_once(HelperPath.DS.'HTMLView.php');
	require_once(ViewPath.DS.'LoginView.php');
	require_once(ViewPath.DS.'MemberView.php');

	class LoginController  {

		private $sessionModel;
		private $loginView;
		private $memberView;
		private $user;
		private $userModel;
		private static $hashString = "sha256";
		private $cookie;
		private $username;
		private $passwordSafe;

		function __construct () {
			$this->sessionModel = new SessionModel();
			$this->loginView = new LoginView();
			$this->memberView = new MemberView();
			$this->userModel = new UserModel();
			$this->cookie = new CookieStorage();
		        $this->user = new User($this->getuser(), $this->getSafePassword());



		}	

		public function getuser() {
			return $this->loginView->GetUsername ();
		}
		public function getSafePassword() {
			return $this->loginView->GetPassword ();
		}



		public function RunLoginLogic () {
			global $remote_ip;
			global $b_ip;
			global $user_agent;

			$onReload = false;

			$loginView = clone $this->loginView;		
			$memberView = clone $this->memberView;
			$sessionModel = clone $this->sessionModel;
			$usermodel = clone $this->userModel;
		
			if($loginView->userPressRegNewUser() == true) {
				$regView->RenderRegForm();
				return true;
			}	
	

			if(!$sessionModel->IsLoggedIn() && !$loginView->UserPressLoginButton()
			 && !$memberView->RememberMe()) {
				$loginView->RenderLoginForm();
				return;
			}

			if ($memberView->UserPressLogoutButton()) {	
				$this->LogoutUser();
				return true;
			}

			if ($loginView->UserPressLoginButton()) {
				$result = $this->AuthenticateUser();
				if ($result === true) {

					$autoLoginIsSet = $loginView->AutoLoginIsChecked();
					$memberView->RenderMemberArea($autoLoginIsSet, $onReload);		
					return true;
				}
				else {

					$loginView->RenderLoginForm($result);
				}
			}
			if ($sessionModel->IsLoggedIn() || $memberView->RememberMe()) {

				$onReload = true;
				$validId = hash(self::$hashString, $remote_ip . $user_agent);

				if ($sessionModel->IsStolen($validId)) {	
					$this->memberView->LogoutUser();
					$this->loginView->RenderLoginForm();
					return false;
				}

				$userN = $this->cookie->GetCookieUsername();

			
				if ($memberView->RememberMe() && ($this->UserCredentialManipulated() || $this->CookieDateManipulated())) {
				
					$this->LogoutUser(false);
					return false;
				}
					$memberView->RenderMemberArea(false, $onReload);
					return true;
			}
		}		

		public function GetUserCookie(){
			$username = $this->loginView->GetUsername();
			return $this->userModel->getUserCookie($username);
			
		}
		protected function AuthenticateUser () {
			$message = $this->loginView->Validate();


			if ($message !== true) {
				
				return $message;
			}
			
			$username = $this->loginView->GetUsername();
			$userAuthenticated = $this->userModel->AuthenticateUser($username);
			$username = $userAuthenticated[1];
			$password = $userAuthenticated[2];
			$pass = $this->loginView->GetPassword();
			$final = crypt($pass, $password);

			$userCookie =  $this->GetUserCookie();
			$usr = $userCookie[1];
			$pws = $userCookie[2];

			if ($final === $password && $userAuthenticated) {
				$this->sessionModel->LoginUser($this->user);
				if ($this->loginView->AutoLoginIsChecked()) {

					$cookieTimestamp = time() + 60;
					$this->memberView->SaveUserCredentials($username, $pws, $cookieTimestamp);
					$this->userModel->SaveCookieTimestamp($cookieTimestamp,$this->sessionModel->GetUsername());
				}

				return true;
			}
			else {

				return $this->loginView->GetLoginErrorMessage();
			}
		}

		protected function UserCredentialManipulated () {

		
			try {

				$username = $this->memberView->GetCookieUsername();
				$password = $this->memberView->GetCookiePassword();				
			}
			catch (\Exception $e) {
				return true;
			}

			return !@$this->userModel->UserCredentialManipulated($username, $password);
		}

		protected function CookieDateManipulated () {
			$username = $this->memberView->GetCookieUsername();
			$currentTime = time();
			$cookieExpTime = ($this->userModel->GetCookieDateById($username));

			if ($currentTime > $cookieExpTime) {

				return true;

			}
			return false;
		}

		protected function LogoutUser ($isDefaultLogout = true) {
			$this->memberView->LogoutUser();
			$this->loginView->RenderLogoutView($isDefaultLogout);
		}
	}