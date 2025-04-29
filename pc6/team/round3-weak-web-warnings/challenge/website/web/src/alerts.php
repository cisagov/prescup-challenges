<style>table, th, td {
  border: 1px solid black;
  border-collapse: collapse;
  padding: 10px;
</style>
<?php

include_once("envHandler.php");

if($_GET["t"] != "")
    $table = $_GET["t"];
else   
    $table = "alerts";

$table = str_ireplace("-", "", $table);
$table = str_ireplace("#", "", $table);
$table = str_ireplace("/", "", $table);
$table = str_ireplace(";", "", $table);
$table = str_ireplace("U", "", $table);

$schema = $env->getDBSchema();

$sql = "SELECT ID, Title, Message FROM $schema.$table WHERE resolved = 0;";

$dbname = $env->getDBSchema();

// Create connection
$conn = new mysqli($env->getDBServer(), $env->dbUser(), $env->dbPass(), $dbname);
// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

$result = $conn->query($sql);

if ($result->num_rows > 0) {
    // output data of each row
    echo "<table>";
    echo "<tr><th>ID</th><th>Name</th><th>Message</th></tr>";
    while($row = $result->fetch_assoc()) {
        echo "<tr><td>" . $row["ID"] . "</td><td>" . $row["Title"] . "</td><td>" . $row["Message"] . "</td></tr>";
    }
    echo "</table>";
} else {
    echo "0 results";
}

$conn->close();

?>
