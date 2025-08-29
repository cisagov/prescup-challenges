<?php

// Copyright 2025 Carnegie Mellon University.
// Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
// root or contact permission@sei.cmu.edu for full terms.

// Enable error reporting
error_reporting(E_ALL);
ini_set('display_errors', 1);

session_start();

// Check if product_id and quantity are provided
if (!isset($_POST['product_id']) || !isset($_POST['quantity'])) {
    header('Location: index.php'); // Redirect to homepage if product_id or quantity is not provided
    exit();
}

$product_id = intval($_POST['product_id']);
$quantity = intval($_POST['quantity']);

// Initialize the shopping cart if it doesn't exist
if (!isset($_SESSION['cart'])) {
    $_SESSION['cart'] = [];
}

// Add product to the cart or update the quantity if it already exists
if (isset($_SESSION['cart'][$product_id])) {
    $_SESSION['cart'][$product_id] += $quantity;
} else {
    $_SESSION['cart'][$product_id] = $quantity;
}

// Redirect to a cart page or a confirmation page
header('Location: cart.php');
exit();
?>
