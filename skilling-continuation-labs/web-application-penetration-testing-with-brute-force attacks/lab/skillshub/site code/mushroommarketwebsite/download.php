<?php

// Copyright 2025 Carnegie Mellon University.
// Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
// root or contact permission@sei.cmu.edu for full terms.

session_start();
if (!isset($_SESSION['user_id'])) {
    header('Location: login.php');
    exit();
}

$file = $_GET['file'];
$file_path = $file; // Directly use the file parameter

if (file_exists($file_path)) {
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="' . basename($file_path) . '"');
    readfile($file_path);
    exit();
} else {
    echo "File not found.";
}
?>

