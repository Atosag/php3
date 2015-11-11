<?php
	
	class HTMLView {

		function echoHTML ($body){
			
			if ($body === null) {
				throw new \Exception("HTMLView->HTMLView does not allow body to be null");
			}

				$time = '[' . strftime("%H:%M:%S") . ']';
				$year = date("Y");
				$month = date("M");
				$day = date("d");

				$sweWeekday = $this->GetSwedishWeekday(date("d"), date("M"), date("Y"));
				$sweMonth = $this->GetSwedishMonth(strftime("%Y"), strftime("%m"), strftime("%d"));
				$date = '<p>' . $sweWeekday . ', den ' . $day . ' ' . $sweMonth . ' år ' . $year . '. ' . 'Klockan är ' . $time . '</p>';			

				echo 
					'<!DOCTYPE HTML>
						<html>
							<head>
								<meta content="text/html; charset=utf-8" http-equiv="content-type">
								<title>PHP</title>
							</head>
							<body>
								<h1>PHP Laboration 3</h1>' .
								$body .
								$date .
							'</body>
						</html>';
		}

		public function GetSwedishWeekday ($day, $month, $yearForDay){

			$weekDay = Array(
				'Monday'=>'Måndag','Tuesday'=>'Tisdag','Wednesday'=>'Onsdag',
				'Thursday'=>'Torsdag','Friday'=>'Fredag','Saturday'=>'Lördag','Sunday'=>'Söndag');

			return $weekDay[date("l", strtotime($yearForDay.'-'.$month.'-'.$day))];
		}

		public function GetSwedishMonth ($year, $month, $day){

			$date = $year.'-'.$month.'-'.$day;

			$month = Array(
				'Jan'=>'Januari','Feb'=>'Februari','Mar'=>'Mars','Apr'=>'April','May'=>'Maj','Jun'=>'Juni','Jul'=>'Juli',
				'Aug'=>'Augusti','Sep'=>'September','Oct'=>'Oktober','Nov'=>'November','Dec'=>'December');
			
			return @$month[strftime("%h", strtotime((string)$date))];
		}
	}