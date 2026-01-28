<?php

// Copyright 2025 Carnegie Mellon University.
// Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
// root or contact permission@sei.cmu.edu for full terms.

session_start();
?>
<!DOCTYPE html>
<html>
<head>
    <title>Register - E-commerce</title>
    <link rel="stylesheet" type="text/css" href="css/style.css">
</head>
<body>
    <header>
        <nav>
            <a href="index.php">Home</a>
            <a href="search.php">Product Search</a>
            <a href="feedback.php">Site Feedback</a>
            <a href="aboutus.php">About Us</a>
            <?php if (isset($_SESSION['username'])): ?>
                <a href="orders.php">My Orders</a>
                <a href="cart.php">View Cart</a>
                <a href="profile.php">My Profile</a>
                <a href="logout.php">Logout</a>
            <?php else: ?>
                <a href="login.php">Login</a>
                <a href="register.php">Register</a>
            <?php endif;?>
        </nav>
    </header>

    <div class="container">
        <h1>Register</h1>
        <form method="post" action="register.php?is_admin=0">
            <div class="form-group">
                <label for="username">Username:</label>
                <input type="text" id="username" name="username" required>
            </div>
            <div class="form-group">
                <label for="password">Password:</label>
                <input type="password" id="password" name="password" required>
            </div>
            <div class="form-group">
                <label for="email">Email:</label>
                <input type="email" id="email" name="email" required>
            </div>
            <button type="submit" name="register">Register</button>
        </form>

        <?php
        if ($_SERVER['REQUEST_METHOD'] == 'POST') {
            $username = $_POST['username'];
            $password = $_POST['password'];
            $email = $_POST['email'];
            $is_admin = isset($_GET['is_admin']) ? $_GET['is_admin'] : 0; // Get is_admin from URL
            $salt = bin2hex(random_bytes(8)); // Generate a random salt
            $hashedPassword = md5($password . $salt);

            include 'includes/db.config.php';
         
            $queryemail = "SELECT id, username, password, salt, is_admin FROM users WHERE email = '$email'";
            $resultemail = $conn->query($queryemail);
            $queryuser = "SELECT id, username, password, salt, is_admin FROM users WHERE username = '$username'";
            $resultuser = $conn->query($queryuser);
            
            if ($resultemail && $resultemail->num_rows > 0) {
                echo "<div class='alert alert-danger'>Email Exists!</div>";
            }

            elseif ($resultuser && $resultuser->num_rows > 0) {
                echo "<div class='alert alert-danger'>Username Exists!</div>";
            }
            
            else {
                $sql = "INSERT INTO users (username, password, salt, email, is_admin) VALUES ('$username', '$hashedPassword', '$salt', '$email', '$is_admin')";
                if ($conn->query($sql) === TRUE) {
                    echo "<div class='alert alert-success'>Registration successful!</div>";
                } 
                else {
                    echo "<div class='alert alert-danger'>Error: " . $sql . "<br>" . $conn->error . "</div>";
                }
            }
            $conn->close();
        }
        ?>
    </div>
</body>
</html>


