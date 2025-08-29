<?php

// Copyright 2025 Carnegie Mellon University.
// Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
// root or contact permission@sei.cmu.edu for full terms.

session_start();
include 'includes/db.config.php';

if (!isset($_SESSION['user_id'])) {
    echo "You must be logged in to view your profile. Return to \r\n";
    echo '<a href="index.php">Home</a>';

    exit;
}

$user_id = $_SESSION['user_id'];

// Fetch user info
$user_sql = "SELECT username, email, is_admin FROM users WHERE id = ?";
$user_stmt = $conn->prepare($user_sql);
$user_stmt->bind_param("i", $user_id);
$user_stmt->execute();
$user_result = $user_stmt->get_result();
$user = $user_result->fetch_assoc();

// Fetch stored cards
$card_sql = "SELECT cardholder_name, last4, expiry_month, expiry_year FROM payments WHERE user_id = ?";
$card_stmt = $conn->prepare($card_sql);
$card_stmt->bind_param("i", $user_id);
$card_stmt->execute();
$card_result = $card_stmt->get_result();
?>
<!DOCTYPE html>
<html>
<head>
    <title>My Profile - E-commerce</title>
    <link rel="stylesheet" type="text/css" href="css/style.css">
</head>
<body>
    <header>
        <nav>
            <a href="index.php">Home</a>
            <a href="search.php">Product Search</a>
            <a href="cart.php">Cart</a>
            <a href="orders.php">My Orders</a>
            <a href="logout.php">Logout</a>
        </nav>
    </header>

    <div class="container">
        <h1>My Profile</h1>
        <div class="user-info">
            <p><strong>Username:</strong> <?php echo htmlspecialchars($user['username']); ?></p>
            <p><strong>Email:</strong> <?php echo htmlspecialchars($user['email']); ?></p>
            <p><strong>Account Type:</strong> <?php echo $user['is_admin'] ? 'Admin' : 'User'; ?></p>
        </div>

        <h2>Stored Payment Methods</h2>
        <ul>
            <?php
            while ($card = $card_result->fetch_assoc()) {
                echo "<li>";
                echo "cardholder name: " . htmlspecialchars($card['cardholder_name']) . "<br>" .
                     "Ending in " . htmlspecialchars($card['last4']) . "<br>" .
                     " (Exp: " . htmlspecialchars($card['expiry_month']) . "/" . 
                     htmlspecialchars($card['expiry_year']) . ")</li>";
            }
            ?>
        </ul>
    </div>
</body>
</html>
