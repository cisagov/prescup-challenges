<?php

// Copyright 2024 Carnegie Mellon University.
// Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
// root or contact permission@sei.cmu.edu for full terms.

$mysqli = new mysqli("localhost","admin","Aurel1an@dm!n","eshop");

if ($mysqli->connect_errno) {
	echo "MYSQL conn. failure: " . $mysqli->connect_error;
	exit;
}

$query = "select * from products";

$result = $mysqli->query($query);

if ($result->num_rows > 0) {
	echo "<table>";
	echo "<tr><th>Product Code</th><th>Name</th><th>Description</th><th>Price ($)</th><th>Current stock</th></tr>";
	while ($row = $result->fetch_assoc()) {
		echo "<tr>";
		echo "<td>" . $row["id"] . "</td>";
		echo "<td>" . $row["name"] . "</td>";
		echo "<td>" . $row["description"] . "</td>";
		echo "<td>" . $row["price"] . "</td>";
		echo "<td>" . $row["quantity"] . "</td>";
		echo "</tr>";
	}
	echo "</table>";
} else {
	echo "No products available.";
}

$mysqli->close();
?>
