<?php
	
	
	defined('DS') ? null : define('DS', DIRECTORY_SEPARATOR);
	defined('ProjectRootPath') ? null : define('ProjectRootPath', '/storage/content/84/198884/atosag.nu/public_html/login3');
	
	defined('HelperPath') ? null : define('HelperPath', ProjectRootPath.DS.'data');
	defined('ModelPath') ? null : define('ModelPath', ProjectRootPath.DS.'src/model');
	defined('ViewPath') ? null : define('ViewPath', ProjectRootPath.DS.'src/view');
	defined('ControllerPath') ? null : define('ControllerPath', ProjectRootPath.DS.'src/controller');


	require_once(HelperPath.DS.'config.php');
	require_once(HelperPath.DS.'SessionModel.php');
	require_once(HelperPath.DS.'Database.php');

	require_once(ModelPath.DS.'UserModel.php');
	require_once(ModelPath.DS.'User.php');

	require_once(HelperPath.DS.'HTMLView.php');
	require_once(ViewPath.DS.'LoginView.php');
	require_once(ViewPath.DS.'MemberView.php');
	require_once(ViewPath.DS.'CookieStorage.php');

	require_once(ControllerPath.DS.'LoginController.php');
	require_once(HelperPath.DS.'safe.php');
	require_once(HelperPath.DS.'setting.php');