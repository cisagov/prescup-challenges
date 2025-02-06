<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login Page</title>
</head>
<!-- Navigation Links -->
<a href="register.php">Register</a> |
<a href="schedule.php">View Schedule</a> |
<a href="upload.php">Upload Documents</a> |
<a href="view_docs.php">View Documents</a> |
<a href="logout.php">Logout</a>

    <h1>Welcome to the Jiffy Car Repair Service Customer Portal</h1>

<body>
    <p>Please log in:</p>


    <form method="POST" action="login.php">
        Username: <input type="text" name="username" required><br>
        Password: <input type="password" name="password" required><br>
        <input type="submit" value="Login">
    </form>

    <br>

</body>
</html>


