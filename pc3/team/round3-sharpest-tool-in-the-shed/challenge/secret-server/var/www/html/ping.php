// Copyright 2022 Carnegie Mellon University.
// Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
// root or contact permission@sei.cmu.edu for full terms.

<?php
if($_SERVER['REQUEST_METHOD'] == 'GET') {
	if($_SERVER['REMOTE_ADDR'] == '10.5.5.10') {
		$data = [ 'alive' => 'true' ];
		header('Content-Type: application/json;charset=utf-8');
		header('Access-Control-Allow-Origin: *');
		http_response_code(200);
		echo json_encode($data);
	} else {
		$data = [ 'error' => 'ONLY FOR ADMIN-TOOLS' ];
		header('Content-Type: application/json;charset=utf-8');
		header('Access-Control-Allow-Origin: *');
		http_response_code(400);
		echo json_encode($data);
	}
}
?>
