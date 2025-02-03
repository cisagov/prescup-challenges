<?php
//Start session
session_start();


// Connect to the SQLite database
$db = new PDO('sqlite:/var/www/html/database/database.db');

// Check if form was submitted
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'];
    $password = $_POST['password'];
    $id="";

    // User SQL query
    $query = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
    $result = $db->query($query);

    if ($result && $result->fetch()) {
        // Store login status in session
        $_SESSION['loggedin'] = true;
        $_SESSION['username'] = $username;
        $_SESSION['user_id'] = $id;  //storing user id for file identification.
        echo "Login successful!";
        // Redirect to the next page
        header("Location: schedule.php");
        exit;
    } else {
        echo "Invalid credentials!";
    }
}
?>

<!-- Navigation Links -->
<a href="index.php">Home</a> |
<a href="schedule.php">View Schedule</a> |
<a href="upload.php">Upload Documents</a> |
<a href="view_docs.php">View Documents</a> |
<a href="logout.php">Logout</a>
<h1> Welcome to the Jiffy Car Repair Service Customer Portal</h1>


<!-- Simple login form -->
<form method="POST" action="login.php">
    Username: <input type="text" name="username" required><br>
    Password: <input type="password" name="password" required><br>
    <input type="submit" value="Login">
</form>

