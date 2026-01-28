<?php

// Copyright 2025 Carnegie Mellon University.
// Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
// root or contact permission@sei.cmu.edu for full terms.

session_start();
include 'includes/db.config.php';

// Initialize variables
$search_query = '';
///////added line
$results = [];

//$sql = "SELECT * FROM products WHERE is_visible = TRUE";

// Process search query if provided
if (isset($_GET['query'])) {
    $search_query = $_GET['query'];

    // Modify SQL to include search conditions
    //$sql = "SELECT * from products where name LIKE '%$search_query%' and is_visible = TRUE";
    
    //new query
    $stmt = $conn->prepare("Select * FROM products WHERE name LIKE CONCAT('%', ?, '%') AND is_visible = TRUE");
    $stmt->bind_param("s", $search_query);
    $stmt->execute();
    $results = $stmt->get_result();
}
else {
    $results = $conn->query("SELECT * FROM products WHERE is_visible = TRUE");
}
?>

<!-- // Execute SQL query
$result = $conn->query($sql);
?> -->

<!DOCTYPE html>
<html>
<head>
    <title>Search Products - E-commerce</title>
    <link rel="stylesheet" type="text/css" href="css/style.css">
    <style>
        /* Additional styles to ensure multiple items per row */
        .row {
            display: flex;
            flex-wrap: wrap;
            gap: 20px;
            justify-content: center; /* Center items horizontally */
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
        <form method="get" action="search.php">
            <input type="text" name="query" value="<?php echo htmlspecialchars($search_query); ?>">
            <button type="submit">Search</button>
        </form>

        <?php
        //Add in reflective XSS code
        if (isset($_GET['query'])) {
            echo "<h1>You Searched for: <strong>" . $_GET['query'] . "</strong></h1>";
        }
        ?>

    
        <?php
        if ($results && $results->num_rows > 0 ){
            echo "<div class='row'>";
            while ($row = $results->fetch_assoc()){
               echo "<div class='card'>";
               echo "<img src='" . $row['image'] . "' alt='" . $row['name'] . "'>";
               echo "<h5>" . $row['name'] . "</h5>";
               echo "<p>Price: $" . $row['price'] . "</p>";
               echo "<p>description: " . $row['description'] . "</p>";
               echo "<a href='product.php?id=" . $row['id'] . "'>View</a>";
               echo "</div>";            
            }
            
        }
        else {
            
            echo "<li>No results found.</li>";
        }    
        echo "</div>";

        // if (!empty($search_query)) { // Display results only if a search query is provided
        //     echo '<h1>Search Results for "' . htmlspecialchars($search_query) . '"</h1>';
        //     echo '<div class="row">';
        //     if ($result) {
        //         if ($result->num_rows > 0) {
        //             while($row = $result->fetch_assoc()) {
        //                 echo "<div class='card'>";
        //                 echo "<img src='" . $row['image'] . "' alt='" . $row['name'] . "'>";
        //                 echo "<h5>" . $row['name'] . "</h5>";
        //                 echo "<p>Price: $" . $row['price'] . "</p>";
        //                 echo "<p>description: " . $row['description'] . "</p>";
        //                 echo "<a href='product.php?id=" . $row['id'] . "'>View</a>";
        //                 echo "</div>";
        //             }
        //         } else {
        //             echo "<p>No products found.</p>";
        //         }
        //     } else {
        //         echo "<p>Error: " . $conn->error . "</p>";
        //     }
        //     echo '</div>'; // Close row
        //
        ?>
        
    </div>
</body>
</html>

<?php
$conn->close();
?>


