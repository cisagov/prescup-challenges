<?php
session_start();
require 'includes/db.config.php'; // Include the database connection

// Function to check if a user is an admin
function isAdmin($username, $conn) {
    $query = "SELECT is_admin FROM users WHERE username = '$username'";
    $result = $conn->query($query);

    if ($result && $result->num_rows > 0) {
        $user = $result->fetch_assoc();
        return $user['is_admin'] == 1;
    } else {
        return false;
    }
}

// Handle form submission
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $username = $_POST['username'];
    $password = $_POST['password'];

    try {
        // Introduce SQL injection vulnerability intentionally
        $query = "SELECT id, username, password, salt, is_admin FROM users WHERE username = '$username'";

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
                $_SESSION['is_admin'] = isAdmin($username, $conn); // Check if user is admin

                echo "<div class='alert alert-success'>Login successful!</div>";
                if ($_SESSION['is_admin']) {
                    echo "<div class='alert alert-info'>You are logged in as an admin, here is your token: ######## </div>";
                }
                header('Location: index.php');
                exit();
            } else {
                echo "<div class='alert alert-danger'>Invalid password.</div>";
            }
        } else {
            echo "<div class='alert alert-danger'>No user found with that username.</div>";
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
            <a href="register.php">Register</a>
            <a href="login.php">Login</a>
        </nav>
    </header>

    <div class="container">
        <h1>Login</h1>
        <form method="post" action="login.php">
            <div class="form-group">
                <label for="username">Username:</label>
                <input type="text" id="username" name="username" required>
            </div>
            <div class="form-group">
                <label for="password">Password:</label>
                <input type="password" id="password" name="password" required>
            </div>
            <button type="submit" name="login">Login</button>
        </form>
    </div>
</body>
</html>


