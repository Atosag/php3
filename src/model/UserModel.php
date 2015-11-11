<?php
	require_once(HelperPath.DS.'Database.php');

	class UserModel extends Database {
		
		private static $username = 'username';
	    private static $password = 'password';
		private static $autologin = "autologin";

			public function __construct () {
				$this->tabel = "user";
			}

		public function AuthenticateUser($username) {

		
			try {
				
				$pdo = $this->connectionToDataBase();
				$sql = "SELECT * from $this->tabel 
				WHERE BINARY ". self::$username ." = ?";
				$params = array($username);
				$query = $pdo->prepare($sql);
				$query->execute($params);
				$result = $query->fetch();
				return $result;

			}catch(PDOException $ex) {

				die('An unknown error hase happened');
			}
		}


		


			


		public function SaveCookieTimestamp ($timestamp, $username) {

			try {
			$newData = new UserModel();			
			$pdo = $newData->connectionToDataBase();
			$sql = "UPDATE $this->tabel
			SET  autologin  = ?
			WHERE  username = ?";
			$params = array($timestamp, $username);
			$query = $pdo->prepare($sql);
			$query->execute($params);

			}
			catch(PDOException $ex) {
				die('An unknown error has happened');
			}
	
		}


		public function GetCookieDateById ($username) {

		try {

			$pdo = $this->connectionToDataBase();
			$sql = "SELECT autologin
			FROM $this->tabel
			WHERE    username =?";
			$params = array($username);
			$query = $pdo->prepare($sql);
			$query->execute($params);
			$result = $query->fetch();
			$timestamp = array_shift($result);	
			return $timestamp;
			}
			catch(PDOException $ex){
				die('An unknown error has happened');
			}
			
		}

			public function getUser($username) {

		
			try {
				
					$newData = new UserModel();			
			$pdo = $newData->connectionToDataBase();
				$sql = "SELECT * from $this->tabel 
				WHERE BINARY ". self::$username ." = ?";
				$params = array($username);
				$query = $pdo->prepare($sql);
				$query->execute($params);
				$result = $query->fetch();
				return $result;

			}catch(PDOException $ex) {

				die('An unknown error hase happened');
			}
		}

			public function getUserCookie($username) {

		
			try {
				
				$newData = new UserModel();			
				$pdo = $newData->connectionToDataBase();
				$sql = "SELECT * from $this->tabel 
				WHERE BINARY ". self::$username ." = ?";
				$params = array($username);
				$query = $pdo->prepare($sql);
				$query->execute($params);
				$result = $query->fetch();
				return $result;

			}catch(PDOException $ex) {

				die('An unknown error hase happened');
			}
		}

		public function UserCredentialManipulated ($username, $data) {
			$ArrayUser = $this->getUser($username);
			$u = $ArrayUser[1];
			$hp = $ArrayUser[2];
			return ($u === $username && $hp === $data);
		}
	}

