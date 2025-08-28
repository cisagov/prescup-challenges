<?php

// Copyright 2025 Carnegie Mellon University.
// Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
// root or contact permission@sei.cmu.edu for full terms.

session_start();
require 'includes/db.config.php'; // Include the database connection
require 'includes/fpdf/fpdf.php'; // Include the FPDF library

// Check if the user is logged in
if (!isset($_SESSION['user_id'])) {
    header('Location: login.php');
    exit();
}

// Function to generate PDF
function generatePDF($orderId, $userId, $total, $conn) {
    // Ensure the invoices directory exists
    $invoicesDir = "invoices";
    if (!is_dir($invoicesDir)) {
        mkdir($invoicesDir, 0777, true);
    }

    // Create a new PDF
    $pdf = new FPDF();
    $pdf->AddPage();
    $pdf->SetFont('Arial', 'B', 16);

    // Add order details to the PDF
    $pdf->Cell(40, 10, 'Order ID: ' . $orderId);
    $pdf->Ln();
    $pdf->Cell(40, 10, 'Order Date: ' . date('Y-m-d H:i:s'));
    $pdf->Ln();
    $pdf->Cell(40, 10, 'Total: ' . $total);

    // Save the PDF in the invoices directory
    $pdf->Output('F', "$invoicesDir/order_$orderId.pdf");
}

// Retrieve cart items and calculate total
$cartTotal = 0;
$cartItems = [];
$contains_hidden_items = false;

if (isset($_SESSION['cart']) && is_array($_SESSION['cart'])) {
    foreach ($_SESSION['cart'] as $productId => $quantity) {
        $query = "SELECT * FROM products WHERE id = '$productId'";
        $result = $conn->query($query);

        if ($result && $result->num_rows > 0) {
            $product = $result->fetch_assoc();
            $subtotal = $product['price'] * $quantity;
            $cartTotal += $subtotal;
            $cartItems[] = $product;

            if (!$product['is_visible']) {
                $contains_hidden_items = true;
            }
        }
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Insert order into database
    $userId = $_SESSION['user_id'];
    $query = "INSERT INTO orders (user_id, total) VALUES ('$userId', '$cartTotal')";
    if ($conn->query($query) === TRUE) {
        $orderId = $conn->insert_id;

        // Insert order details
        foreach ($cartItems as $item) {
            $productId = $item['id'];
            $quantity = $_SESSION['cart'][$productId];
            $query = "INSERT INTO order_details (order_id, product_id, quantity) VALUES ('$orderId', '$productId', '$quantity')";
            $conn->query($query);
        }

        // Generate PDF invoice
        generatePDF($orderId, $userId, $cartTotal, $conn);

        // Clear the cart
        unset($_SESSION['cart']);

        // Redirect to index with success message
        $_SESSION['order_success'] = true;
        header('Location: index.php');
        exit();
    } else {
        echo "Error: " . $query . "<br>" . $conn->error;
    }
}

$conn->close();
?>

<!DOCTYPE html>
<html>
<head>
    <title>Checkout - E-commerce</title>
    <link rel="stylesheet" type="text/css" href="css/style.css">
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
    </header>

    <div class="container">
        <h1>Checkout</h1>
        <form method="post" action="checkout.php">
            <table>
                <tr>
                    <th>Product</th>
                    <th>Quantity</th>
                    <th>Price</th>
                    <th>Subtotal</th>
                </tr>
                <?php foreach ($cartItems as $item): ?>
                <tr>
                    <td><?php echo $item['name']; ?></td>
                    <td><?php echo $_SESSION['cart'][$item['id']]; ?></td>
                    <td>$<?php echo $item['price']; ?></td>
                    <td>$<?php echo $item['price'] * $_SESSION['cart'][$item['id']]; ?></td>
                </tr>
                <?php endforeach; ?>
                <tr>
                    <td colspan="3"><strong>Total</strong></td>
                    <td><strong>$<?php echo $cartTotal; ?></strong></td>
                </tr>
            </table>
            <button type="submit">Place Order</button>
        </form>
        <?php
        if ($contains_hidden_items) {
            echo "<p>TOKEN: ########</p>";
        }
        ?>
    </div>
</body>
</html>


