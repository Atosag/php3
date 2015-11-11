<?php

    class safe{


      public function create_hash($passwordOne){
            $salt = strtr(base64_encode(mcrypt_create_iv(PBKDF2_SALT_BYTE_SIZE, MCRYPT_DEV_URANDOM)), '+', '.');
            $salt = sprintf(PBKDF2_HASH,PBKDF2_ITERATIONS) . $salt;
            $safe = crypt($passwordOne,$salt);
            return  $safe;
        }

    }   