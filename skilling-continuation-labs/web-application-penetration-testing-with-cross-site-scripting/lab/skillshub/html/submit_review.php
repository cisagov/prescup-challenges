<?php

// Copyright 2025 Carnegie Mellon University.
// Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
// root or contact permission@sei.cmu.edu for full terms.

session_start();
include 'includes/db.config.php';

if (!isset($_SESSION['username'])) {
    header("Location: login.php");
    exit();
}

if (!isset($_GET['id']) || !is_numeric($_GET['id'])) {
    header("Location: index.php");
    exit();
}

$product_id = intval($_GET['id']);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $rating = intval($_POST['rating']);
    $content = trim($_POST['content']);
    $username = $_SESSION['username'];

    if ($rating >= 1 && $rating <= 5 && !empty($content)) {
        $stmt = $conn->prepare("INSERT INTO reviews (product_id, username, rating, content, created_at) VALUES (?, ?, ?, ?, NOW())");
        $stmt->bind_param("isis", $product_id, $username, $rating, $content);
        $stmt->execute();
        $stmt->close();
        header("Location: product.php?id=$product_id");
        exit();
    } else {
        $error = "Invalid rating or empty review.";
    }
}
?>
<!DOCTYPE html>
<html>
<head>
    <title>Submit Review</title>
    <link rel="stylesheet" type="text/css" href="css/style.css">
    <style>
        body {
            font-family: sans-serif;
            background-color: #4C9BFB;
            margin: 0;
            padding: 0;
        }
        .container {
            max-width: 700px;
            margin: 40px auto;
            background: tan;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 2px 2px 10px rgba(0,0,0,0.1);
        }
        form {
            margin-top: 20px;
        }
        label {
            font-weight: bold;
        }
        select, textarea, input[type="submit"] {
            width: 100%;
            padding: 10px;
            margin-top: 8px;
            margin-bottom: 20px;
            border: 1px solid #ccc;
            border-radius: 5px;
        }
        input[type="submit"] {
            background-color: #4CAF50;
            color: white;
            cursor: pointer;
            font-weight: bold;
        }
        input[type="submit"]:hover {
            background-color: #45a049;
        }
        .error {
            color: red;
            font-weight: bold;
        }
        .back-link {
            margin-top: 20px;
        }
    </style>
</head>
<body>
    <header>
        <nav>
            <a href="index.php">Home</a>
            <a href="search.php">Product Search</a>
            <a href="aboutus.php">About Us</a>
            <?php if (isset($_SESSION['username'])): ?>
                <a href="orders.php">My Orders</a>
                <a href="cart.php">View Cart</a>
                <a href="logout.php">Logout</a>
            <?php else: ?>
                <a href="login.php">Login</a>
                <a href="register.php">Register</a>
            <?php endif;?>
        </nav>
    </header>

    <div class="container">
        <h1>Submit a Review</h1>
        <?php if (isset($error)): ?>
            <p class="error"><?php echo $error; ?></p>
        <?php endif; ?>

        <form method="post">
            <label for="rating">Rating (1–5 stars):</label>
            <select name="rating" id="rating" required>
                <option value="">--Choose--</option>
                <option value="5">★★★★★</option>
                <option value="4">★★★★☆</option>
                <option value="3">★★★☆☆</option>
                <option value="2">★★☆☆☆</option>
                <option value="1">★☆☆☆☆</option>
            </select>

            <label for="content">Your Review:</label>
            <textarea name="content" id="content" rows="5" required></textarea>

            <input type="submit" value="Submit Review">
        </form>

        <div class="back-link">
            <a href="product.php?id=<?php echo $product_id; ?>">← Back to Product</a>
        </div>
    </div>
</body>
</html>

