<?php

// Copyright 2024 Carnegie Mellon University.
// Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
// root or contact permission@sei.cmu.edu for full terms.

session_start();

if ($_SESSION["is_authenticated"] && $_SESSION["isadmin"] == 0) {
	// User content here
	echo "Welcome to user space";
} else {
    header("Location: index.html");
    exit();
}
?>
