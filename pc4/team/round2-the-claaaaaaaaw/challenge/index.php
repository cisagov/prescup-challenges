<!--
Copyright 2023 Carnegie Mellon University.
Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
root or contact permission@sei.cmu.edu for full terms.
-->

<!DOCTYPE HTML>
<html>
<head>
<style>
.error {color: #FF0000;}
body {
background-color: #D3D3D3;
}
</style>
</head>
<body>
<?php
// define variables and set to empty values
$nameErr = "";
$name = "";

if ($_SERVER["REQUEST_METHOD"] == "POST") {
  if (empty($_POST["name"])) {
    $nameErr = "ID is required";
  } else {
    $name = test_input($_POST["name"]);
    // check if name only contains letters and whitespace
    if (!preg_match("/^[1-9][0-9]{0,15}$/",$name)) {
      $nameErr = "Only 1-16 numbers allowed";
    }
  }
}

function test_input($data) {
  $data = trim($data);
  $data = stripslashes($data);
  $data = htmlspecialchars($data);
  return $data;
}
?>

<h2>Collection of Linguistics from Alien Worlds</h2>
<h4>15 second delay for approval/denial by superior. Allow time for this request to be processed.</h4>
<p><span class="error">* required field</span></p>
<form method="post" action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]);?>">
  Connection ID: <input type="text" name="name" value="<?php echo $name;?>">
  <span class="error">* <?php echo $nameErr;?></span>
  <br><br>
  <input type="submit" name="submit" value="Request">
</form>

<?php
echo "<h2>Results:</h2>";
if ($name != '' and $nameErr == '') {
  sleep(15);	
  $output = shell_exec("mysql -u username -p'SETPASSWORDHERE' -D pc -h 127.0.0.1 -P 3306 -e 'SELECT * from phone_logs where Connection_ID=$name;'"); #Set the username and password
  if ($output != '') {
	  echo "<pre>$output</pre>";
  }
  else {
	  echo "NO REASONABLE SUSPICIOUS RESULTS FOUND. REQUEST DENIED.";
  }
}
echo "<br>";
?>
</body>
</html>
