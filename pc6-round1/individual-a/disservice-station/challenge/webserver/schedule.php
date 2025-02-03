<!-- Navigation Links -->
<a href="index.php">Home</a> |
<a href="schedule.php">View Schedule</a> |
<a href="upload.php">Upload Documents</a> |
<a href="view_docs.php">View Documents</a> |
<a href="logout.php">Logout</a>

<h1> Welcome to the Jiffy Car Repair Service Customer Portal</h1>

<?php
// Start the session
session_start();

// Check if the user is logged in
if (!isset($_SESSION['loggedin']) || $_SESSION['loggedin'] !== true) {
    header("Location: index.php");
    exit;
}

// Connect to the SQLite database
$db = new PDO('sqlite:/var/www/html/database/database.db');

// Query for the user's repair schedule
$username = $_SESSION['username'];
$query = "SELECT * FROM repairs WHERE username = '$username'";
$result = $db->query($query);

// Fetch repair schedule
if ($result) {
    $repair = $result->fetch();
    if ($repair) {
        echo "<h1>Repair Schedule for " . htmlspecialchars($username) . "</h1>";
        echo "<p>Car: " . htmlspecialchars($repair['car_model']) . "</p>";
        echo "<p>Status: " . htmlspecialchars($repair['status']) . "</p>";
        echo "<p>Estimated Completion: " . htmlspecialchars($repair['completion_date']) . "</p>";
    } else {
        echo "<p>No repair scheduled for your account.</p>";
    }
} else {
    echo "Error retrieving repair schedule.";
}
?>


