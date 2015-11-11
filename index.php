<?php
	
	session_start();

	$remote_ip = $_SERVER['REMOTE_ADDR'];
	$user_agent = $_SERVER['HTTP_USER_AGENT'];

	if (!isset($_SESSION['LoginValues'])) {
		
		$_SESSION['LoginValues']['username'] = '';
	}

	require_once("data/pathConfig.php");
	
	$loginController = new LoginController();
	$loginController->RunLoginLogic();

	