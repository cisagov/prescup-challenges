<?php

// Copyright 2025 Carnegie Mellon University.
// Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
// root or contact permission@sei.cmu.edu for full terms.

session_start();
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
            justify-content: center; /* Center the cards */
        }
        .card {
            width: 250px; /* Adjust width as needed */
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

    <div class="container">
        <?php
        if (isset($_SESSION['username'])) {
            $username = $_SESSION['username'];
            echo "<h1>Welcome to Mushroom Market, $username</h1>";

    //  // Check if the logged-in user is "bcampbell"
    //         if ($_SESSION['username'] === 'bcampbell') {
    //             echo "<h1 style='color:DodgerBlue;'>bcampbell password cracked token = ########</p>";
    //         }

    //         // Check if user is admin
    //         if (isset($_SESSION['is_admin']) && $_SESSION['is_admin'] === '1' ) {
    //             echo "<h1 style='color:DodgerBlue;'>You are logged in as an admin, here is your token: ######## </h1>";
    //         }
        } else {
            echo "<h1>Welcome to the Mushroom Market! please log in</h1>";
        }
        ?>
        <h2>Products</h2>
        <div class="row">
            <?php
            include 'includes/db.config.php';

            $sql = "SELECT * FROM products WHERE is_visible = 1";
            $result = $conn->query($sql);

            if ($result) {
                if ($result->num_rows > 0) {
                    while($row = $result->fetch_assoc()) {
                        echo "<div class='card'>";
                        echo "<img src='" . $row['image'] . "' alt='" . $row['name'] . "'>";
                        echo "<h5>" . $row['name'] . "</h5>";
                        echo "<p>Price: $" . $row['price'] . "</p>";
                        echo "<a href='product.php?id=" . $row['id'] . "'>View</a>";
                        echo "</div>";
                    }
                } else {
                    echo "<p>No products found.</p>";
                }
            } else {
                echo "<p>Error: " . $conn->error . "</p>";
            }
            $conn->close();
            ?>
        </div>
    </div>
</body>
</html>


