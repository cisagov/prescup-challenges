/**
 * This setups the Minerva skin.
 * It should run without errors even if MobileFrontend is not installed.
 */
var ms = require( 'mobile.startup' ),
	addPortletLink = require( './addPortletLink.js' );

function init() {
	var permissions = mw.config.get( 'wgMinervaPermissions' ) || {},
		// eslint-disable-next-line no-jquery/no-global-selector
		$watch = $( '#page-actions-watch' );

	if ( permissions.watch && !mw.user.isAnon() ) {
		require( './watchstar.js' ).init( $watch );
	}

	addPortletLink.init();
	mw.hook( 'util.addPortletLink' ).add(
		addPortletLink.hookHandler
	);

	// Setup Minerva with MobileFrontend
	if ( ms && !ms.stub ) {
		require( './initMobile.js' )();
	} else {
		// MOBILEFRONTEND IS NOT INSTALLED.
		// setup search for desktop Minerva at mobile resolution without MobileFrontend.
		require( './searchSuggestReveal.js' )();
	}

	// This hot fix should be reviewed and possibly removed circa January 2021.
	// It's assumed that Apple will prioritize fixing this bug in one of its next releases.
	// See T264376.
	if ( navigator.userAgent.match( /OS 14_[0-9]/ ) ) {
		document.body.classList.add( 'hotfix-T264376' );
	}
}

init();

module.exports = {
	// Version number allows breaking changes to be detected by other extensions
	VERSION: 1
};
