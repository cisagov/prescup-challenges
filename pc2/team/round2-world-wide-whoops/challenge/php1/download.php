// Copyright 2022 Carnegie Mellon University.
// Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
// root or contact permission@sei.cmu.edu for full terms.

<?php
if(isset($_REQUEST["file"])){
    $file = urldecode($_REQUEST["file"]); // Decode URL-encoded string

    if(preg_match('/^[^.][-a-z0-9_.]+[a-z]$/i', $file)){
        $filepath = "./" . $file;

        if(strpos($file, 'token')!==false){
            die("Cannot request the token file from your IP address");
        }

        else{
            // Process download
            if(file_exists($filepath)) {
                header('Content-Description: File Transfer');
                header('Content-Type: application/octet-stream');
                header('Content-Disposition: attachment; filename="'.basename($filepath).'"');
                header('Expires: 0');
                header('Cache-Control: must-revalidate');
                header('Pragma: public');
                header('Content-Length: ' . filesize($filepath));
                flush(); // Flush system output buffer
                readfile($filepath);
                die("File downloaded");
            } else{
                die("File does not exist");
            }
        }
    } else {
        if(strpos($file, 'http')!==false){
            $content = file_get_contents($file);

            if($content===false){
                die("Failed to download file contents");
            }
            echo $content;
        }
        else{
            die("Check given file name");
        }
    }
}
