<?php

// Copyright 2025 Carnegie Mellon University.
// Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
// root or contact permission@sei.cmu.edu for full terms.

session_start();
include 'includes/db.config.php';


$username = $_SESSION['username'] ?? 'anonymous';

// Handle submission (stored XSS)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['message'])) {
    $msg = $_POST['message'];
    $stmt = $conn->prepare("INSERT INTO feedback (username, message) VALUES (?, ?)");
    $stmt->bind_param("ss", $username, $msg);
    $stmt->execute();
    $stmt->close();
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>Home - E-commerce</title>
    <link rel="stylesheet" type="text/css" href="css/style.css">
    <style>
        .row {
            display: flex;
            flex-wrap: wrap;
            gap: 20px;
            justify-content: center;
        }
        .card {
            width: 250px;
            border: 1px solid #ccc;
            padding: 10px;
            text-align: center;
        }
        .card img {
            max-width: 100%;
            height: auto;
        }
    </style>
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


<!DOCTYPE html>
<html>
<head>
    <title>Feedback</title>
    <style>
       
        textarea {
            width: 100%;
            height: 80px;
        }
        input[type="submit"] {
            padding: 10px 20px;
            background: #007bff;
            border: none;
            color: white;
            border-radius: 5px;
            margin-top: 10px;
        }
        .feedback-entry {
            border-top: 1px solid #ddd;
            margin-top: 20px;
            padding-top: 10px;
        }
    </style>
</head>
<body>
<div class="container">
    <h1>Feedback Page</h1>

    <!-- Reflected XSS -->
    <?php if (isset($_GET['note'])): ?>
        <p><strong>Note:</strong> <?php echo $_GET['note']; ?></p>
    <?php endif; ?>

    <!-- DOM XSS -->
    <p id="info-box"></p>

    <form method="POST">
        <label for="message">Leave feedback:</label><br>
        <textarea name="message" id="message" required></textarea><br>
        <input type="submit" value="Submit Feedback">
    </form>

    <h2>Previous Feedback</h2>
    <?php
    $result = $conn->query("SELECT username, message, created_at FROM feedback ORDER BY created_at DESC");
    while ($row = $result->fetch_assoc()) {
        echo "<div class='feedback-entry'>";
        echo "<strong>{$row['username']}</strong> at {$row['created_at']}<br>";
        echo $row['message'];
        echo "</div>";
    }
    ?>
</div>

<!-- DOM-based XSS via ?info=... -->
<script>
    const params = new URLSearchParams(window.location.search);
    const info = params.get("info");
    if (info) {
        document.getElementById("info-box").innerHTML = "Extra Info: " + info;
    }
</script>
</body>
</html>
