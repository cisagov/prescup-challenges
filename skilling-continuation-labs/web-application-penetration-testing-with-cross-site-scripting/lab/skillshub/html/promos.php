<?php

// Copyright 2025 Carnegie Mellon University.
// Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
// root or contact permission@sei.cmu.edu for full terms.

session_start();
?>
<!DOCTYPE html>
<html>
<head>
    <title><?php echo "Promotions"; ?> - E-commerce</title>
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
<body>
    <div class="container">
        <h1 style="color:yellow;">Current Promotions</h1>

        <div class="promo">
            <h2 style="color:beige; text-align:left"><img src="images/promo/sun.png" alt="Sunny" style="height:96px; vertical-align:middle; margin-right:8px;">Summer Sale - Up to 50% Off</h2>
            <h3 style="color:blue; text-align:center;">Our biggest sale of the year! Limited-time discounts on all categories.</h3>
        </div>

        <div class="promo">
            <h2 style="color:beige; text-align:left"><img src="images/promo/box.png" alt="FUN" style="height:96px; vertical-align:middle; margin-right:8px;">Free Gift With Every Order</h2>
            <h3 style="color:blue; text-align:center;">All purchases this week come with a mystery gift. Don't miss out!</h3></span>
        </div>

        
        <a id="couponlink" href="#">Apply Coupons</a>
    </div>

    <script>
        const params = new URLSearchParams(window.location.search);
        const action = params.get("apply");
        if (action) {
            document.getElementById("couponlink").setAttribute("onclick", action);
        }
        else {
            document.getElementById("couponlink").setAttribute("onclick", "alert('Coupons applied to your account!');");
        }
    </script>
</body>
</html>

