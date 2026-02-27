<?php

// phpcs:disable Generic.NamingConventions.CamelCapsFunctionName.NotCamelCaps
// phpcs:disable MediaWiki.Commenting.FunctionComment.WrongStyle
// phpcs:disable MediaWiki.NamingConventions.PrefixedGlobalFunctions

// Run with: 'php ./dodo.test.php'

require_once __DIR__ . '/../vendor/autoload.php';

// Call this at each point of interest, passing a descriptive string
function prof_flag( $str ) {
	global $prof_timing, $prof_names;
	$prof_timing[] = microtime( true );
	$prof_names[] = $str;
}

// Call this when you're done and want to see the results
function prof_print() {
	global $prof_timing, $prof_names;
	$size = count( $prof_timing );
	for ( $i = 0;$i < $size - 1; $i++ ) {
		// echo "<b>{$prof_names[$i]}</b><br>";
		//echo sprintf("&nbsp;&nbsp;&nbsp;%f<br>", $prof_timing[$i+1]-$prof_timing[$i]);

		echo $prof_names[$i] . ": " . strval( $prof_timing[$i + 1] - $prof_timing[$i] ) . "\n";
		// echo sprintf("&nbsp;&nbsp;&nbsp;%f<br>", $prof_timing[$i+1]-$prof_timing[$i]);
	}
	echo "\n\n" . $prof_names[$size - 1];
	// echo "<b>{$prof_names[$size-1]}</b><br>";
}

/******************************************************************************
 * This is just a demo to show basic invocation.
 * It is not intended to provide test coverage of any kind.
 */

$dom = new Wikimedia\Dodo\Document( '1.0', 'UTF-8' );

$html = $dom->createElement( "html" );
$body = $dom->createElement( "body" );
$comment = $dom->createComment( 'Hello, world!' );

$p = [];

prof_flag( "create" );

for ( $i = 0; $i < 10000; $i++ ) {
		$p[] = $dom->createElement( "p" );
}

prof_flag( "append" );

for ( $i = 0; $i < 10000 - 1; $i++ ) {
		$p[$i]->appendChild( $p[$i + 1] );
}

$p2 = [];
for ( $i = 0; $i < 10000; $i++ ) {
		$p2[] = $dom->createElement( "p" );
}

prof_flag( "unsafeappend" );

for ( $i = 0; $i < 10000 - 1; $i++ ) {
		$p2[$i]->_unsafeAppendChild( $p2[$i + 1] );
}

prof_flag( "append final" );

$body->appendChild( $p[0] );
$body->appendChild( $p2[0] );
$html->appendChild( $body );
$dom->appendChild( $html );

prof_flag( "done" );

echo prof_print();

/* Print the tree */
echo $dom->saveHTML();
