<?php

// Copyright 2024 Carnegie Mellon University.
// Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
// root or contact permission@sei.cmu.edu for full terms.

$mysqli = new mysqli("localhost","admin","Aurel1an@dm!n","eshop");

if ($mysqli->connect_errno) {
	echo "MYSQL conn. failure: " . $mysqli->connect_error;
	exit;
}

$userid = $_POST["userid"];
$query = "select users.firstname, users.lastname, products.name, purchases.quantity, purchases.timestamp from users, products, purchases where users.id=purchases.user_id and products.id=purchases.product_id and users.id=".$userid;

$mysqli->multi_query($query);

do {
	if ($result = $mysqli->store_result()) {
		echo "<table>";
		echo "<tr><th>CUST. NAME</th><th>PRODUCT NAME</th><th>QUANTITY</th><th>PURCHASE DATE</th></tr>";
		while ($row = $result->fetch_row()) {
			echo "<tr><td>" . $row[0] . " " . $row[1] ."</td><td>".$row[2]."</td><td>".$row[3]."</td><td>".$row[4]."</td></tr>";
		}
		echo "</table>";
	}
	if ($mysqli->more_results()) {
		printf("-----------------------------------\n");
	}
} while ($mysqli->next_result());
$mysqli->close();
?>
