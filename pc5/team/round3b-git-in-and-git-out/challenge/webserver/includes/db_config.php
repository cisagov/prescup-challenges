<?php

// Copyright 2024 Carnegie Mellon University.
// Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
// root or contact permission@sei.cmu.edu for full terms.

$servername = "10.2.2.100";
$username = "webservice";
$password = "M9FKpGa5t4kqcVP6";
$database = "website";

$conn = new mysqli($servername, $username, $password, $database);

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}
?>

