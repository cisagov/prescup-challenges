var watchstar = mw.loader.require( 'mediawiki.page.watch.ajax' ).watchstar;

( function () {

	var WATCHED_CLASS = [ 'watched', 'mw-ui-icon-wikimedia-unStar-progressive' ],
		TEMP_WATCHED_CLASS = [ 'temp-watched', 'mw-ui-icon-wikimedia-halfStar-progressive' ],
		UNWATCHED_CLASS = 'mw-ui-icon-wikimedia-star-base20';

	/**
	 * Tweaks the global watchstar handler in core to use the correct classes for Minerva.
	 *
	 * @param {jQuery.Object} $icon
	 */
	function init( $icon ) {
		var $watchlink = $icon.find( 'a' );
		watchstar( $watchlink, mw.config.get( 'wgRelevantPageName' ), toggleClasses );
	}

	/**
	 *
	 * @param {jQuery.Object} $link
	 * @param {boolean} isWatched
	 * @param {string} expiry
	 */
	function toggleClasses( $link, isWatched, expiry ) {
		$link.removeClass(
			[].concat( WATCHED_CLASS, TEMP_WATCHED_CLASS, UNWATCHED_CLASS )
		).addClass( function () {
			var classes = UNWATCHED_CLASS;
			if ( isWatched ) {
				if ( expiry !== null && expiry !== undefined && expiry !== 'infinity' ) {
					classes = TEMP_WATCHED_CLASS;
				} else {
					classes = WATCHED_CLASS;
				}
			}
			return classes;
		} );
	}

	module.exports = {
		init: init,
		test: {
			toggleClasses: toggleClasses
		}
	};

}() );
