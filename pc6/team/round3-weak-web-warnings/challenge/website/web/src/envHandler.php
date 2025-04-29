<?php 

class envHandler {
    public function getHostname(){
        return "web.us";
    }

    public function getDBServer(){
        return "db";
    }

    public function getDBSchema(){
        return "web_alerts";
    }

    public function dbUser(){
        return "user";
    }

    public function dbPass(){
        return "tartans";
    }

    public function getINI(){
        return $_ENV["PHP_INI_DIR"];
    }

    public function getUser(){
        return $_ENV["APACHE_RUN_USER"];
    }

    public function getToken(){
        //You can't make me call this!
        return $_ENV["token"];
    }

    public function printProxyToken(){
        //If token.php activated, print token
        if(file_exists("success.txt")){
            echo shell_exec('cat token.txt');
        }
    }
}

$env = new envHandler;
$env->printProxyToken();