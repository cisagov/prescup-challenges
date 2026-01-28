<?php
$upload_dir = "uploads/";
$filename = basename($_FILES["file"]["name"]);
$target_file = $upload_dir . $filename;

if (move_uploaded_file($_FILES["file"]["tmp_name"], $target_file)) {
    echo "Upload successful. <a href='/uploads/" . htmlspecialchars($filename) . "'>Download your file</a>";
} else {
    echo "Upload failed.";
}
?>
