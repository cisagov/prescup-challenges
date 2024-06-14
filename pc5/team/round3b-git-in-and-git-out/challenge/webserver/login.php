<?php

// Copyright 2024 Carnegie Mellon University.
// Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
// root or contact permission@sei.cmu.edu for full terms.

session_start();
include 'includes/db_config.php';

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $username = mysqli_real_escape_string($conn, $_POST['username']);
    $password = mysqli_real_escape_string($conn, $_POST['password']);

    $sql = "SELECT id, username, isadmin FROM users WHERE username='$username' AND password='$password'";
    $result = $conn->query($sql);

    if ($result->num_rows == 1) {
        $row = $result->fetch_assoc();
	
	#cache in redis
	
	$_SESSION["user_id"] = $row["id"];
        $_SESSION["is_authenticated"] = true;
	$_SESSION["isadmin"] = $row["isadmin"];

        if ($row["isadmin"] == 1) {
            header("Location: admin.php");
            exit();
        } else {
            header("Location: user.php");
            exit();
        }
    } else {
        header("Location: index.html?login_error=1");
        exit();
    }
}

$conn->close();
?>
