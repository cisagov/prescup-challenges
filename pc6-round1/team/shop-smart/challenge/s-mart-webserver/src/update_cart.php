<?php
// Enable error reporting
error_reporting(E_ALL);
ini_set('display_errors', 1);

session_start();

// Check if cart exists
if (!isset($_SESSION['cart'])) {
    $_SESSION['cart'] = [];
}

// Check if an update or remove action was requested
if (isset($_POST['update']) && isset($_POST['quantities'][$_POST['update']])) {
    $product_id = intval($_POST['update']);
    $quantity = intval($_POST['quantities'][$product_id]);

    if ($quantity > 0) {
        $_SESSION['cart'][$product_id] = $quantity;
    }
} elseif (isset($_POST['remove'])) {
    $product_id = intval($_POST['remove']);

    if (isset($_SESSION['cart'][$product_id])) {
        unset($_SESSION['cart'][$product_id]);
    }
} elseif (isset($_POST['update_all']) && isset($_POST['quantities'])) {
    foreach ($_POST['quantities'] as $product_id => $quantity) {
        $product_id = intval($product_id);
        $quantity = intval($quantity);

        if ($quantity > 0) {
            $_SESSION['cart'][$product_id] = $quantity;
        }
    }
}

// Redirect back to the cart page
header('Location: cart.php');
exit();
?>


