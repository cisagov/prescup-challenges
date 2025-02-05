<!DOCTYPE html>
<html>
<head>
    <title>My Orders - E-commerce</title>
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
        <h1>My Orders</h1>
        <?php
        session_start();
        if (!isset($_SESSION['user_id'])) {
            header('Location: login.php');
            exit();
        }

        $userId = $_SESSION['user_id'];
        require 'includes/db.config.php'; // Include the database connection

        // Check if the logged-in user is "jsdavis"
        if ($_SESSION['username'] === 'bcampbell') {
            echo "<p>Token = ########</p>";
        }

        $query = "SELECT * FROM orders WHERE user_id = '$userId'";
        $result = $conn->query($query);

        if ($result && $result->num_rows > 0) {
            echo "<table>";
            echo "<tr><th>Order ID</th><th>Date</th><th>Total</th><th>Download</th></tr>";
            while ($order = $result->fetch_assoc()) {
                echo "<tr>";
                echo "<td>" . $order['id'] . "</td>";
                echo "<td>" . $order['order_date'] . "</td>";
                echo "<td>" . $order['total'] . "</td>";
                echo "<td><a href='download.php?file=invoices/order_" . $order['id'] . ".pdf'>Download</a></td>";
                echo "</tr>";
            }
            echo "</table>";
        } else {
            echo "<p>You have no orders.</p>";
        }
        ?>
    </div>
</body>
</html>


