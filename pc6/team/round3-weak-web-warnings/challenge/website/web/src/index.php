<?php

// Do some security checks

//Passed, load page

include_once("envHandler.php");

$webhost = $env->getHostname();

if (strpos(strtolower($_GET["page"]), 'token') !== false) {
    echo "Sneaky sneaky, but you can't request token.php that way!";
}
else if($_GET["page"] == ""){
    echo "<h1>Internal Web Alerts Page</h1>";
    echo "<p>View Security Alerts: <a href='http://$webhost/alerts?t=Alerts'>Events</a></p>";
    echo "<p>View Other Events: <a href='http://$webhost/alerts?t=Events'>Events</a></p>";
    echo "<p>Monitored Hosts: <a href='http://$webhost/hosts'>Hosts</a></p>";
}
else{
    include($_GET["page"] . ".php");
}

?>