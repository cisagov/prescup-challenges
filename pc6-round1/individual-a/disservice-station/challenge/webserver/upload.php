<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Upload Registration & Insurance Info</title>
</head>
<!-- Navigation Links -->
<a href="index.php">Home</a> |
<a href="schedule.php">View Schedule</a> |
<a href="view_docs.php">View Documents</a> |
<a href="logout.php">Logout</a>

<h1> Welcome to the Jiffy Car Repair Service Customer Portal</h1>
<h2>Upload Your Registration & Insurance Info</h2>
<br>
<?php
// Start the session
session_start();

// Check if the user is logged in, if not redirect to login page
if (!isset($_SESSION['loggedin']) || $_SESSION['loggedin'] !== true) {
    header('Location: login.php');
    exit;
}

// Connect to the SQLite database
$db = new PDO('sqlite:/var/www/html/database/database.db');

// Process file upload
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $target_dir = "uploads/";
    $target_file = $target_dir . basename($_FILES["file"]["name"]);
    $user_id = $_SESSION['user_id'];

    if (move_uploaded_file($_FILES["file"]["tmp_name"], $target_file)) {
        // Insert file info into the database
        $query = "INSERT INTO uploads (user_id, filename, upload_date) VALUES (?, ?, ?)";
        $stmt = $db->prepare($query);
        $stmt->execute([$user_id, basename($_FILES["file"]["name"]), date('Y-m-d H:i:s')]);

        echo "The file " . htmlspecialchars(basename($_FILES["file"]["name"])) . " has been uploaded.";
    } else {
        echo "Sorry, there was an error uploading your file.";
    }
}
?>

<!-- File upload form -->
<form action="upload.php" method="POST" enctype="multipart/form-data">
    Select file to upload:
    <input type="file" name="file" id="file" required>
    <input type="submit" value="Upload File" name="submit">
</form>


