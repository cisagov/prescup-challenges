<style>table, th, td {
  border: 1px solid black;
  border-collapse: collapse;
  padding: 10px;
}
div{
    width: 200px;  
    word-break: break-all;
}
</style>

<?php 

//Comment token: TOKENSOURCE

include_once("envHandler.php");

class Host{
    private $hostname;
    private $user;
    private $password;

    function __construct($name, $user, $pass){
        $this->hostname = $name;
        $this->user = $user;
        $this->password = $pass;
    }

    public function getHostname(){
        return $this->hostname;
    }

    public function getUser(){
        return $this->user;
    }

    public function getToken(){
        return $this->password;
    }
}

class HostHandler{
    private $hosts;

    function __construct($hosts){
        $this->hosts = $hosts;
    }

    public function printHosts(){
        echo "<table>";
        echo "<tr><th>Host</th><th>User</th><th>Security Token</th></tr>";
        foreach($this->hosts as $host){
            echo "<tr><td>" . $host->getHostname() . "</td><td>" . $host->getUser() . "</td><td>" . $host->getToken() . "</td></tr>";
        }
        echo "</table>";
    }
}

$defaultHosts = [new Host("www.irc.com", "hackerman", "hunter2"), new Host("kali.us", "user", "tartans"), new Host("www.business-site.com", "user", "MySecretPassword123!")];

$hosts = new HostHandler($defaultHosts);

if($_POST["import"] != ""){
    $hosts = unserialize(base64_decode($_POST["import"]));
}

echo "<h1>Monitored Hosts</h1>";

$hosts->printHosts();

?>

<p>*Note that the import feature is only partially implemented at this time and will not save to database.</p>

<p>Export string:</p>
<div><code><?php echo base64_encode(serialize($hosts)); ?></code></div>
<form action="/hosts" method="post">
    <label for="import">Import String:</label>
    <input type="text" id="import" name="import">
    <input type="submit" value="Submit">
</form>
