<?php
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
            <a href="register.php">Register</a>
            <a href="login.php">Login</a>
            <a href="orders.php">My Orders</a>
            <a href="cart.php">View Cart</a>
            <a href="logout.php">Logout</a>
        </nav>
    </header>

    <div class="container">
        <?php
        if (isset($_SESSION['username'])) {
            $username = $_SESSION['username'];
            echo "<h1>Welcome to S-Mart, $username</h1>";

            // Check if user is admin
            if (isset($_SESSION['is_admin']) && $_SESSION['is_admin']) {
                echo "<h1>You are logged in as an admin, here is your token: ######## </h1>";
            }
        } else {
            echo "<h1>Welcome to S-Mart, Carrying everything except chainsaws since 1993! please log in</h1>";
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


