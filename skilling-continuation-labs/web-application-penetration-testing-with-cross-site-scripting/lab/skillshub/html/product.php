<?php

// Copyright 2025 Carnegie Mellon University.
// Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
// root or contact permission@sei.cmu.edu for full terms.

session_start();
include 'includes/db.config.php';

// Check if product id is provided in the URL
if (!isset($_GET['id'])) {
    header('Location: index.php'); // Redirect to homepage if no product id is provided
    exit();
}

$product_id = intval($_GET['id']);

// Retrieve product details from the database
$sql = "SELECT * FROM products WHERE id = ?";
$stmt = $conn->prepare($sql);
$stmt->bind_param("i", $product_id);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows > 0) {
    $product = $result->fetch_assoc();
} else {
    header('Location: index.php'); // Redirect to homepage if product id is invalid
    exit();
}
$stmt->close();
?>
<!DOCTYPE html>
<html>
<head>
    <title><?php echo $product['name']; ?> - E-commerce</title>
    <link rel="stylesheet" type="text/css" href="css/style.css">
    <style>
        .product-card {
            background: #fff;
            border: 1px solid #ccc;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 2px 2px 8px rgba(0,0,0,0.1);
            margin-bottom: 30px;
        }
        .product-image img {
            max-width: 300px;
            height: auto;
            display: block;
            margin-bottom: 15px;
        }
        .review {
            background: #fff;
            border: 1px solid #ccc;
            border-radius: 8px;
            padding: 15px;
            margin-bottom: 20px;
            box-shadow: 1px, 1px, 6px rgba(0,0,0,0.05);
            padding-bottom: 10px;
        }
        .review hr {
            border: none;
            border-bottom: 1px solid #eee;
            margin-top: 10px;
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
                <a href="logout.php">Logout</a>
            <?php else: ?>
                <a href="login.php">Login</a>
                <a href="register.php">Register</a>
            <?php endif;?>
        </nav>
    </header>

    <div class="container">
        <h1><?php echo $product['name']; ?></h1>
        <div class="product-details">
            <div class="product-image">
                <img src="<?php echo $product['image']; ?>" alt="<?php echo $product['name']; ?>">
            </div>
            <div class="product-info">
                <p><strong>Price:</strong> $<?php echo $product['price']; ?></p>
                <p><strong>Description:</strong> <?php echo $product['description']; ?></p>
            </div>
        </div>

        <?php if (isset($_SESSION['username'])): ?>
            <div style="margin-bottom: 20px;">
                <a href="submit_review.php?id=<?php echo $product_id; ?>">
                    <button>Add a Review</button>
                </a>
            </div>
        <?php endif; ?>

        <label for="filter">Filter by Rating:</label>
        <select id="filter">
            <option value ="">ShowAll</option>
            <option value ="5">★★★★★</option>
            <option value ="4">★★★★☆</option>
            <option value ="3">★★★☆☆</option>
            <option value ="2">★★☆☆☆</option>
            <option value ="1">★☆☆☆☆</option>
        </select>
        <p id="filter-status"></p>

        <h2>Customer Reviews</h2>
        <?php
        // Load reviews
        include 'includes/db.config.php';
        $stmt = $conn->prepare("SELECT username, rating, content, created_at FROM reviews WHERE product_id = ?");
        $stmt->bind_param("i", $product_id);
        $stmt->execute();
        $review_result = $stmt->get_result();

        if ($review_result->num_rows > 0) {
            while ($review = $review_result->fetch_assoc()) {
                $stars = str_repeat("★", $review['rating']) . str_repeat("☆", 5 - $review['rating']);
                echo "<div class='review'>";
                echo "<p><strong>{$review['username']}</strong> rated it: $stars</p>";
                echo "<p>{$review['content']}</p>";
                echo "<small>Posted on {$review['created_at']}</small>";
                echo "<hr></div>";
            }
        } else {
            echo "<p>No reviews yet for this product.</p>";
        }
        $stmt->close();
        $conn->close();
        ?>
    </div>
</body>
</html>

<script>
    const filter = document.getElementById("filter");
    const status = document.getElementById("filter-status");

    filter.addEventListener("change", () => {
        const selected = filter.value;

        // DOM XSS vulnerability here — intentionally left unsanitized
        if (!selected) {
            status.innerHTML = "Showing all reviews";
        } else {
            status.innerHTML = "Showing only: " + selected + " star reviews";
        }

        document.querySelectorAll(".review").forEach((div) => {
            let line = div.querySelector("p")?.textContent || "";
            if (!selected || line.includes(`rated it: ${"★".repeat(selected)}${"☆".repeat(5 - selected)}`)) {
                div.style.display = "block";
            } else {
                div.style.display = "none";
            }
        });
    });
</script>
