<?php
session_start();
include 'includes/db.config.php';

// Initialize variables
$search_query = '';
$sql = "SELECT * FROM products WHERE is_visible = TRUE";

// Process search query if provided
if (isset($_GET['query'])) {
    $search_query = $_GET['query'];

    // Modify SQL to include search conditions
    $sql = "SELECT * from products where name LIKE '%$search_query%' and is_visible = TRUE";
}

// Execute SQL query
$result = $conn->query($sql);
?>

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
            <a href="register.php">Register</a>
            <a href="login.php">Login</a>
            <a href="orders.php">My Orders</a>
            <a href="cart.php.php">View Cart</a>
            <a href="logout.php">Logout</a>
        </nav>
    </header>

    <div class="container">
        <form method="get" action="search.php">
            <input type="text" name="query" value="<?php echo htmlspecialchars($search_query); ?>">
            <button type="submit">Search</button>
        </form>

        <?php
        if (!empty($search_query)) { // Display results only if a search query is provided
            echo '<h1>Search Results for "' . htmlspecialchars($search_query) . '"</h1>';
            echo '<div class="row">';
            if ($result) {
                if ($result->num_rows > 0) {
                    while($row = $result->fetch_assoc()) {
                        echo "<div class='card'>";
                        echo "<img src='" . $row['image'] . "' alt='" . $row['name'] . "'>";
                        echo "<h5>" . $row['name'] . "</h5>";
                        echo "<p>Price: $" . $row['price'] . "</p>";
                        echo "<p>description: " . $row['description'] . "</p>";
                        echo "<a href='product.php?id=" . $row['id'] . "'>View</a>";
                        echo "</div>";
                    }
                } else {
                    echo "<p>No products found.</p>";
                }
            } else {
                echo "<p>Error: " . $conn->error . "</p>";
            }
            echo '</div>'; // Close row
        }
        ?>

    </div>
</body>
</html>

<?php
$conn->close();
?>


