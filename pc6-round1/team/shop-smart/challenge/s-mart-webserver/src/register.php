<!DOCTYPE html>
<html>
<head>
    <title>Register - E-commerce</title>
    <link rel="stylesheet" type="text/css" href="css/style.css">
</head>
<body>
    <header>
        <nav>
            <a href="index.php">Home</a>
            <a href="search.php">Product Search</a>
            <a href="register.php">Register</a>
            <a href="login.php">Login</a>
        </nav>
    </header>

    <div class="container">
        <h1>Register</h1>
        <form method="post" action="register.php?is_admin=0">
            <div class="form-group">
                <label for="username">Username:</label>
                <input type="text" id="username" name="username" required>
            </div>
            <div class="form-group">
                <label for="password">Password:</label>
                <input type="password" id="password" name="password" required>
            </div>
            <div class="form-group">
                <label for="email">Email:</label>
                <input type="email" id="email" name="email" required>
            </div>
            <button type="submit" name="register">Register</button>
        </form>

        <?php
        if ($_SERVER['REQUEST_METHOD'] == 'POST') {
            $username = $_POST['username'];
            $password = $_POST['password'];
            $email = $_POST['email'];
            $is_admin = isset($_GET['is_admin']) ? $_GET['is_admin'] : 0; // Get is_admin from URL
            $salt = bin2hex(random_bytes(8)); // Generate a random salt
            $hashedPassword = md5($password . $salt);

            include 'includes/db.config.php';


            $sql = "INSERT INTO users (username, password, salt, email, is_admin) VALUES ('$username', '$hashedPassword', '$salt', '$email', '$is_admin')";

            if ($conn->query($sql) === TRUE) {
                echo "<div class='alert alert-success'>Registration successful!</div>";
            } else {
                echo "<div class='alert alert-danger'>Error: " . $sql . "<br>" . $conn->error . "</div>";
            }

            $conn->close();
        }
        ?>
    </div>
</body>
</html>


