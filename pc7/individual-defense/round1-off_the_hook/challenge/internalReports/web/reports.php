<?php
$type = $_GET['type'];
$query = $_GET['query'];

// Business is booming! This is getting a little much to manage like this
// Should migrate to database soon? Need to hire another unpaid intern...

$cmd = "/var/data/search.sh " . escapeshellarg($type) . " " . $query;

$output = [];
$return_code = 0;

exec($cmd . " 2>&1", $output, $return_code);

$lines = array_filter($output);

if (count($lines) > 0) {
    echo "<h2>Search Results</h2>";
    echo "<table border='1' cellpadding='5' cellspacing='0'>";

    $header = str_getcsv(array_shift($lines));
    echo "<thead><tr>";
    foreach ($header as $col) {
        echo "<th>" . htmlspecialchars($col) . "</th>";
    }
    echo "</tr></thead><tbody>";

    foreach ($lines as $line) {
        $fields = str_getcsv($line);
        echo "<tr>";
        foreach ($fields as $field) {
            echo "<td>" . htmlspecialchars($field) . "</td>";
        }
        echo "</tr>";
    }

    echo "</tbody></table>";
} else {
    echo "<p>No results found.</p>";
}
?>
