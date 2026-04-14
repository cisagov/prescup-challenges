( function () {
	var watchstar = require( '../../../resources/skins.minerva.scripts/watchstar.js' ),
		toggleClasses = watchstar.test.toggleClasses,
		WATCHED_CLASS = [ 'watched', 'mw-ui-icon-wikimedia-unStar-progressive' ],
		TEMP_WATCHED_CLASS = [ 'temp-watched', 'mw-ui-icon-wikimedia-halfStar-progressive' ],
		UNWATCHED_CLASS = 'mw-ui-icon-wikimedia-star-base20';

	QUnit.module( 'Minerva Watchstar' );

	function createElemWithClass( cssClass ) {
		return $( '<div/>' ).addClass( cssClass );
	}

	QUnit.test( 'toggleClasses() from watched to unwatched', function ( assert ) {
		var $elem = createElemWithClass( WATCHED_CLASS );
		toggleClasses( $elem, false );
		assert.deepEqual( $elem.attr( 'class' ), UNWATCHED_CLASS );
	} );

	QUnit.test( 'toggleClasses() from unwatched to watched', function ( assert ) {
		var $elem = createElemWithClass( UNWATCHED_CLASS );
		toggleClasses( $elem, true, null );
		assert.deepEqual( $elem.attr( 'class' ).split( /\s+/ ), WATCHED_CLASS );
	} );

	QUnit.test( 'toggleClasses() from unwatched to temp watched', function ( assert ) {
		var $elem = createElemWithClass( UNWATCHED_CLASS );
		toggleClasses( $elem, true, 'expiry' );
		assert.deepEqual( $elem.attr( 'class' ).split( /\s+/ ), TEMP_WATCHED_CLASS );
	} );

	QUnit.test( 'toggleClasses() from temp watched to watched', function ( assert ) {
		var $elem = createElemWithClass( TEMP_WATCHED_CLASS );
		toggleClasses( $elem, true, null );
		assert.deepEqual( $elem.attr( 'class' ).split( /\s+/ ), WATCHED_CLASS );
	} );

}() );
