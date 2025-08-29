<?php

// Copyright 2025 Carnegie Mellon University.
// Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
// root or contact permission@sei.cmu.edu for full terms.

session_start();
require 'includes/db.config.php'; // Include the database connection

// Handle form submission
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $email = $_POST['email'];
    $password = $_POST['password'];

    try {
        // Introduce SQL injection vulnerability intentionally
        $query = "SELECT id, username, password, salt, is_admin FROM users WHERE email = '$email'";

        $result = $conn->query($query);

        if ($result && $result->num_rows > 0) {
            $user = $result->fetch_assoc();
            $stored_password = $user['password'];
            $salt = $user['salt'];

            // Calculate the salted password hash to compare with stored password
            $salted_password = md5($password . $salt);

            if ($salted_password === $stored_password) {
                $_SESSION['user_id'] = $user['id'];
                $_SESSION['username'] = $user['username'];
                $_SESSION['is_admin'] = $user['is_admin']; // Check if user is admin

                echo "<div class='alert alert-success'>Login successful!</div>";
                if ($_SESSION['is_admin'] === '1' ) {
                    echo "<div class='alert alert-info'>You are logged in as an admin, here is your token: ######## </div>";
                }
                header('Location: index.php');
                exit();
            } else {
                echo "<div class='alert alert-danger'>Invalid password.</div>";
            }
        } else {
            echo "<div class='alert alert-danger'>No user found with that Email.</div>";
        }
    } catch (Exception $e) {
        // Log the error for debugging purposes (in production, this should be logged to a file)
        error_log("MySQLi Error: " . $e->getMessage());
        echo "<div class='alert alert-danger'>An error occurred. Please try again later.</div>";
    }
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>Login - E-commerce</title>
    <link rel="stylesheet" type="text/css" href="css/style.css">
</head>
<body>
    <header>
        <nav>
            <a href="index.php">Home</a>
            <a href="search.php">Product Search</a>
            <a href="aboutus.php">About Us</a>
            <?php if (isset($_SESSION['username'])): ?>
                <a href="logout.php">Logout</a>
            <?php else: ?>
                <a href="login.php">Login</a>
                <a href="register.php">Register</a>
            <?php endif;?>
        </nav>
    </header>

    <div class="container">
        <?php if (isset($_SESSION['username'])): ?>
            <h1>Logout of <?=($_SESSION['username']) ?></h1>
            <form method="post" action="logout.php">
                <button type="submit">Logout</button>
            </form>
        <?php else: ?>
            <h1>Please Log In:</h1>
            <form method="post" action="login.php">
                <div class="form-group">
                    <label for="email">Email:</label>
                    <input type="text" id="email" name="email" required>
                </div>
                <div class="form-group">
                    <label for="password">Password:</label>
                    <input type="password" id="password" name="password" required>
                </div>
                <button type="submit" name="login">Login</button>
            </form>
        <?php endif;?>
    </div>
</body>
</html>
