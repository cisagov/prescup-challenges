<?php
// Enable error reporting
error_reporting(E_ALL);
ini_set('display_errors', 1);

session_start();

// Assuming you have already established a database connection
include 'includes/db.config.php';

// Initialize the cart if it doesn't exist
if (!isset($_SESSION['cart'])) {
    $_SESSION['cart'] = [];
}

// Fetch product details from the database
$cart_products = [];
foreach ($_SESSION['cart'] as $product_id => $quantity) {
    $sql = "SELECT * FROM products WHERE id = ?";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("i", $product_id);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows > 0) {
        $product = $result->fetch_assoc();
        $product['quantity'] = $quantity;
        $cart_products[] = $product;
    }

    $stmt->close();
}

$conn->close();
?>

<!DOCTYPE html>
<html>
<head>
    <title>Shopping Cart - E-commerce</title>
    <link rel="stylesheet" type="text/css" href="css/style.css">
</head>
<body>
    <header>
        <nav>
            <a href="index.php">Home</a>
            <a href="search.php">Product Search</a>
            <a href="register.php">Register</a>
            <a href="login.php">Login</a>
            <a href="orders.php">My Orders</a>
            <a href="logout.php">Logout</a>
        </nav>
    </header>


    <div class="container">
        <h1>Shopping Cart</h1>
        <?php if (!empty($cart_products)): ?>
            <form method="post" action="update_cart.php">
                <table>
                    <thead>
                        <tr>
                            <th>Product</th>
                            <th>Quantity</th>
                            <th>Price</th>
                            <th>Total</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($cart_products as $product): ?>
                            <tr>
                                <td><?php echo $product['name']; ?></td>
                                <td>
                                    <input type="number" name="quantities[<?php echo $product['id']; ?>]" value="<?php echo $product['quantity']; ?>" min="1" required>
                                </td>
                                <td>$<?php echo $product['price']; ?></td>
                                <td>$<?php echo $product['quantity'] * $product['price']; ?></td>
                                <td>
                                    <button type="submit" name="update" value="<?php echo $product['id']; ?>">Update</button>
                                    <button type="submit" name="remove" value="<?php echo $product['id']; ?>">Remove</button>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
                <button type="submit" name="update_all">Update All Quantities</button>
            </form>
            <a href="checkout.php">Proceed to Checkout</a>
        <?php else: ?>
            <p>Your cart is empty.</p>
        <?php endif; ?>
    </div>
</body>
</html>


