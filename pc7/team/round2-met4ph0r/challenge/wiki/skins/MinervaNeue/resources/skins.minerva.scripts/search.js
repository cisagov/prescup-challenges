module.exports = function () {
	var
		// eslint-disable-next-line no-restricted-properties
		M = mw.mobileFrontend,
		mobile = M.require( 'mobile.startup' ),
		SearchOverlay = mobile.search.SearchOverlay,
		SearchGateway = mobile.search.SearchGateway,
		overlayManager = mobile.OverlayManager.getSingleton(),
		// eslint-disable-next-line no-jquery/no-global-selector
		$searchInput = $( '#searchInput' ),
		placeholder = $searchInput.attr( 'placeholder' ),
		defaultSearchPage = $searchInput.siblings( 'input[name=title]' ).val(),
		// eslint-disable-next-line no-jquery/no-global-selector
		$searchBar = $( '#searchInput, #searchIcon, .skin-minerva-search-trigger' ),
		searchRoute = new RegExp( /\/search/ ),
		searchOverlayInstance;

	// Only continue on mobile devices as it breaks desktop search
	// See https://phabricator.wikimedia.org/T108432
	if ( mw.config.get( 'skin' ) !== 'minerva' ) {
		return;
	}

	/**
	 * Hide the search overlay on pageload before the search route
	 * is registered with the overlayManager.
	 * Allows the usage of history.back() to close searchOverlay by
	 * preventing the situation described in https://phabricator.wikimedia.org/T102946
	 */
	function removeSearchOnPageLoad() {
		if ( searchRoute.test( overlayManager.router.getPath() ) ) {
			// TODO: replace when router supports replaceState https://phabricator.wikimedia.org/T189173
			history.replaceState( '', document.title, window.location.pathname );
		}
	}

	function getSearchOverlay() {
		if ( !searchOverlayInstance ) {
			searchOverlayInstance = new SearchOverlay( {
				router: overlayManager.router,
				gatewayClass: SearchGateway,
				api: new mw.Api(),
				searchTerm: $searchInput.val(),
				placeholderMsg: placeholder,
				defaultSearchPage: defaultSearchPage
			} );
		}
		return searchOverlayInstance;
	}

	removeSearchOnPageLoad();
	overlayManager.add( searchRoute, getSearchOverlay );

	// Apparently needed for main menu to work correctly.
	$searchBar.prop( 'readonly', true );

	/**
	 * Trigger overlay on touchstart so that the on-screen keyboard on iOS
	 * can be triggered immidiately after on touchend. The keyboard can't be
	 * triggered unless the element is already visible.
	 * Touchstart makes the overlay visible, touchend brings up the keyboard afterwards.
	 */
	$searchBar.on( 'touchstart click', function ( ev ) {
		ev.preventDefault();
		overlayManager.router.navigate( '/search' );
	} );

	$searchBar.on( 'touchend', function ( ev ) {
		ev.preventDefault();
		/**
		 * Manually triggering focus event because on-screen keyboard only
		 * opens when `focus()` is called from a "user context event",
		 * Calling it from the route callback above (which calls SearchOverlay#show)
		 * doesn't work.
		 * http://stackoverflow.com/questions/6837543/show-virtual-keyboard-on-mobile-phones-in-javascript
		 */
		getSearchOverlay().showKeyboard();
	} );

};
