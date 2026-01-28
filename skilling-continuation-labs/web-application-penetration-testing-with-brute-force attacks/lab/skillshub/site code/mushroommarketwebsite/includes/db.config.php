<?php
// db.config.php
$servername = "localhost";
$dbusername = "website";
$dbpassword = "tartans@1";
$dbname = "ecommerce";

// Create connection
$conn = new mysqli($servername, $dbusername, $dbpassword, $dbname);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}
?>

