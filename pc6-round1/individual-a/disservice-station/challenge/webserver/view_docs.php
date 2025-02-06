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

// Get the current user's uploaded files
$user_id = $_SESSION['user_id'];
$query = "SELECT * FROM uploads WHERE user_id = ?";
$stmt = $db->prepare($query);
$stmt->execute([$user_id]);

$uploads = $stmt->fetchAll(PDO::FETCH_ASSOC);
?>

<!-- Navigation Links -->
<a href="index.php">Home</a> |
<a href="schedule.php">View Schedule</a> |
<a href="upload.php">Upload Documents</a> |
<a href="view_docs.php">View Documents</a> |
<a href="logout.php">Logout</a>
<h1> Welcome to the Jiffy Car Repair Service Customer Portal</h1>
<h2>Your Uploaded Documents</h2>

<?php if (count($uploads) > 0): ?>
    <ul>
        <?php foreach ($uploads as $upload): ?>
            <li>
                <a href="uploads/<?php echo htmlspecialchars($upload['filename']); ?>" target="_blank">
                    <?php echo htmlspecialchars($upload['filename']); ?>
                </a> (Uploaded on <?php echo $upload['upload_date']; ?>)
            </li>
        <?php endforeach; ?>
    </ul>
<?php else: ?>
    <p>No documents uploaded yet.</p>
<?php endif; ?>


