// Copyright 2022 Carnegie Mellon University.
// Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
// root or contact permission@sei.cmu.edu for full terms.

<?php
    session_start();
    // Remove code between this line and below if it is given to competitors
    $server="127.0.0.1";
    $user="root";
    $pw="Tartans@1!";
    $db="VULN";
    $conn = mysqli_connect($server, $user, $pw, $db);
    if(!$conn){
        die("DB Connection Failed" . mysqli_connect_error());
    }
    mysqli_query($conn, "UPDATE `users` SET `ID`=1,`Username`='admin',`Password`=\"vp2p4w87kxmqjeam\" WHERE 1");
    // Infinity should change the password......................................... ^here^

    // Remove code above here if it is given to competitors

    $error = "";
    if(isset($_POST['register'])){
        $sql = "SELECT id FROM users WHERE Username = '" . $_POST['register'] ."'";
        $res = mysqli_query($conn, $sql);

        if(mysqli_num_rows($res) > 0){
            $error = "This user is already registered";
        }
        else{
            $error = "Registration is currently disabled";
        }
    }

    else if(isset($_POST['username']) && isset($_POST['password'])){
        $username = mysqli_real_escape_string($conn, $_POST['username']);
        $password = mysqli_real_escape_string($conn, $_POST['password']);
        $sql = "SELECT id FROM users WHERE Username='$username' and Password='$password'";
        $res = mysqli_query($conn, $sql);
        if(mysqli_num_rows($res) == 1){
            die("The token to submit is admin's password");
        }   
        else {
            $error = "Invalid username or password!";
        }
    }
?>

<html>
    <body>
        <h2>Please login or register here:</h2><br>
        <?php echo $error;?>
        <form action="" method="post">
            <label>Username : </label><input type="text" name="username" /><br/>
            <label>Password : </label><input type="password" name="password" /><br/>
            <input type="submit" value="Login" />
        </form>
        <br>
        <form action="" method="post">
            <label>Register Username : </label><input type="text" name="register" /><br/>
            <input type="submit" value="Register" />
        </form>
    </body>
</html>