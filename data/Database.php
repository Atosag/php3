<?php

	abstract class Database {

		protected $connection;
		protected $tabel;
		
	public function connectionToDataBase(){

			if ($this->connection == NULL) {

				$this->connection = new PDO(DB_CONNECTION_STRING, DB_USER_NAME, DB_PASSWORD);

				$this->connection->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

				return $this->connection;
			}
		}
		
	}

	