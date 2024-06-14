<?php

// Copyright 2024 Carnegie Mellon University.
// Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
// root or contact permission@sei.cmu.edu for full terms.

$mysqli = new mysqli("localhost","admin","Aurel1an@dm!n","eshop");

if ($mysqli->connect_errno) {
	echo "MYSQL conn. failure: " . $mysqli->connect_error;
	exit;
}

$query = "select users.firstname, users.lastname, products.name, purchases.quantity, purchases.timestamp from users, products, purchases where users.id=purchases.user_id and products.id=purchases.product_id";

$result = $mysqli->query($query);

if ($result->num_rows > 0) {
	echo "<table>";
	echo "<tr><th>CUST. NAME</th><th>PRODUCT NAME</th><th>QUANTITY</th><th>PURCHASE DATE</th></tr>";
	while ($row = $result->fetch_assoc()) {
		echo "<tr>";
		echo "<td>" . $row['firstname'] . " " . $row['lastname'] . "</td>";
		echo "<td>" . $row['name'] . "</td>";
		echo "<td>" . $row['quantity'] . "</td>";
		echo "<td>" . $row['timestamp'] . "</td>";
		echo "</tr>";
	}
	echo "</table>";
} else {
	echo "No purchases.";
}

$mysqli->close();
?>
