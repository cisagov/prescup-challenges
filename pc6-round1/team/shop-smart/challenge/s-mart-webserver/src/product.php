<?php
// Assuming you have already established a database connection and retrieved product details
include 'includes/db.config.php';

// Check if product id is provided in the URL
if (!isset($_GET['id'])) {
    header('Location: index.php'); // Redirect to homepage if no product id is provided
    exit();
}

$product_id = $_GET['id'];

// Retrieve product details from the database
$sql = "SELECT * FROM products WHERE id = ?";
$stmt = $conn->prepare($sql);
$stmt->bind_param("i", $product_id);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows > 0) {
    $product = $result->fetch_assoc();
} else {
    // Redirect to homepage if product id is invalid
    header('Location: index.php');
    exit();
}

$stmt->close();
$conn->close();
?>

<!DOCTYPE html>
<html>
<head>
    <title><?php echo $product['name']; ?> - E-commerce</title>
    <link rel="stylesheet" type="text/css" href="css/style.css">
</head>
<body>
    <header>
        <nav>
            <a href="index.php">Home</a>
            <a href="search.php">Product Search</a>
            <a href="register.php">Register</a>
            <a href="login.php">Login</a>
            <a href="cart.php">View Cart</a>
            <a href="orders.php">My Orders</a>
            <a href="logout.php">Logout</a>
        </nav>
    </header>


    <div class="container">
        <h1><?php echo $product['name']; ?></h1>
        <div class="product-details">
            <div class="product-image">
                <img src="<?php echo $product['image']; ?>" alt="<?php echo $product['name']; ?>">
            </div>
            <div class="product-info">
                <p><strong>Description:</strong> <?php echo $product['description']; ?></p>
                <p><strong>Price:</strong> $<?php echo $product['price']; ?></p>
                <form method="post" action="add_to_cart.php">
                    <input type="hidden" name="product_id" value="<?php echo $product['id']; ?>">
                    <label for="quantity">Quantity:</label>
                    <input type="number" id="quantity" name="quantity" value="1" min="1" required>
                    <button type="submit" name="add_to_cart">Add to Cart</button>
                </form>
            </div>
        </div>
    </div>
</body>
</html>


