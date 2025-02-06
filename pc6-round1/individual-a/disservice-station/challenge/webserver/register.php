<?php
// Connect to the SQLite database
$db = new PDO('sqlite:/var/www/html/database/database.db');

// Check if form was submitted
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'];
    $password = $_POST['password'];
    $confirm_password = $_POST['confirm_password'];

    // Check if password and confirm password match
    if ($password !== $confirm_password) {
        echo "Passwords do not match!";
    } else {
        // Check if username already exists
        $query = "SELECT * FROM users WHERE username = ?";
        $stmt = $db->prepare($query);
        $stmt->execute([$username]);

        if ($stmt->fetch()) {
            echo "Username already exists!";
        } else {
            // insert new record into users db
            $query = "INSERT INTO users (username, password) VALUES (?, ?)";
            $stmt = $db->prepare($query);
            $stmt->execute([$username, $password]);

            echo "Registration successful!";
        }
    }
}
?>

<!-- Navigation Links -->
<a href="index.php">Home</a> |
<a href="schedule.php">View Schedule</a> |
<a href="upload.php">Upload Documents</a>
<a href="view_docs.php">View Documents</a> |
<a href="logout.php">Logout</a>
<h1> Welcome to the Jiffy Car Repair Service Customer Portal</h1>

<body>

<!-- Simple registration form -->
<form method="POST" action="register.php">
    Username: <input type="text" name="username" required><br>
    Password: <input type="password" name="password" required><br>
    Confirm Password: <input type="password" name="confirm_password" required><br>
    <input type="submit" value="Register">
</form>

</body>
