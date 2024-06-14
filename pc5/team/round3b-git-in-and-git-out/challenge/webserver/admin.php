<?php

// Copyright 2024 Carnegie Mellon University.
// Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
// root or contact permission@sei.cmu.edu for full terms.

session_start();

if ($_SESSION["is_authenticated"] && $_SESSION["isadmin"] == 1) {
	// Admin content here
	$fileContents = file_get_contents("../token");
	echo "<pre>Token: " . htmlspecialchars($fileContents) . "</pre>";

} else {
    header("Location: index.html");
    exit();
}
?>
