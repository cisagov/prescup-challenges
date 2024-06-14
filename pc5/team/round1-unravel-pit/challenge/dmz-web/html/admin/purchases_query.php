<?php

// Copyright 2024 Carnegie Mellon University.
// Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
// root or contact permission@sei.cmu.edu for full terms.

$mysqli = new mysqli("localhost","admin","Aurel1an@dm!n","eshop");

if ($mysqli->connect_errno) {
	echo "MYSQL conn. failure: " . $mysqli->connect_error;
	exit;
}

$query = "select id, firstname, lastname, email from users";

$result = $mysqli->query($query);

if ($result->num_rows > 0) {
	echo "<table>";
	echo "<tr><th>USER ID NUM.</th><th>CUST. NAME</th><th>EMAIL</th><tr>";
	while ($row = $result->fetch_assoc()) {
		echo "<tr>";
		echo "<td>" . $row['id'] . "</td>";
		echo "<td>" . $row['firstname'] . " " . $row['lastname'] . "</td>";
		echo "<td>" . $row['email'] . "</td>";
		echo "</tr>";
	}
	echo "</table>";
} else {
	echo "No users.";
}

$mysqli->close();
?>
<!DOCTYPE html>
<html>
<head>
	<title>Purchases Query</title>
</head>
<body>
	<h2>Purchases Query</h2>
	<form method="POST" action="purchases.php">
		<label for="userid">User ID Number:</label><input type="text" name="userid" id="userid" required>
		<button type="submit">Search</button>
	</form>
</body>
</html>
