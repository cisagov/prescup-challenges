( function ( M, track ) {
	var MAX_PRINT_TIMEOUT = 3000,
		printSetTimeoutReference = 0,
		mobile = M.require( 'mobile.startup' ),
		icons = mobile.icons,
		lazyImageLoader = mobile.lazyImages.lazyImageLoader,
		browser = mobile.Browser.getSingleton();

	/**
	 * Helper function to retrieve the Android version
	 *
	 * @ignore
	 * @param {string} userAgent User Agent
	 * @return {number|false} An integer.
	 */
	function getAndroidVersion( userAgent ) {
		var match = userAgent.toLowerCase().match( /android\s(\d\.]*)/ );
		return match ? parseInt( match[ 1 ] ) : false;
	}

	/**
	 * Helper function to retrieve the Chrome/Chromium version
	 *
	 * @ignore
	 * @param {string} userAgent User Agent
	 * @return {number|false} An integer.
	 */
	function getChromeVersion( userAgent ) {
		var match = userAgent.toLowerCase().match( /chrom(e|ium)\/(\d+)\./ );
		return match ? parseInt( match[ 2 ] ) : false;
	}

	/**
	 * Checks whether DownloadIcon is available for given user agent
	 *
	 * @memberof DownloadIcon
	 * @instance
	 * @param {Window} windowObj
	 * @param {Page} page to download
	 * @param {string} userAgent User agent
	 * @param {number[]} supportedNamespaces where printing is possible
	 * @return {boolean}
	 */
	function isAvailable( windowObj, page, userAgent, supportedNamespaces ) {
		var androidVersion = getAndroidVersion( userAgent ),
			chromeVersion = getChromeVersion( userAgent );

		// Download button is restricted to certain namespaces T181152.
		// Not shown on missing pages
		// Defaults to 0, in case cached JS has been served.
		if ( supportedNamespaces.indexOf( page.getNamespaceId() ) === -1 ||
			page.isMainPage() || page.isMissing ) {
			// namespace is not supported or it's a main page
			return false;
		}

		if ( browser.isIos() || chromeVersion === false ||
			windowObj.chrome === undefined
		) {
			// we support only chrome/chromium on desktop/android
			return false;
		}
		if ( ( androidVersion && androidVersion < 5 ) || chromeVersion < 41 ) {
			return false;
		}
		return true;
	}
	/**
	 * onClick handler for button that invokes print function
	 *
	 * @param {HTMLElement} portletItem
	 * @param {Icon} spinner
	 */
	function onClick( portletItem, spinner ) {
		var icon = portletItem.querySelector( '.mw-ui-icon-minerva-download' );
		function doPrint() {
			printSetTimeoutReference = clearTimeout( printSetTimeoutReference );
			track( 'minerva.downloadAsPDF', {
				action: 'callPrint'
			} );
			window.print();
			$( icon ).show();
			spinner.$el.hide();
		}

		function doPrintBeforeTimeout() {
			if ( printSetTimeoutReference ) {
				doPrint();
			}
		}
		// The click handler may be invoked multiple times so if a pending print is occurring
		// do nothing.
		if ( !printSetTimeoutReference ) {
			track( 'minerva.downloadAsPDF', {
				action: 'fetchImages'
			} );
			$( icon ).hide();
			spinner.$el.show();
			// If all image downloads are taking longer to load then the MAX_PRINT_TIMEOUT
			// abort the spinner and print regardless.
			printSetTimeoutReference = setTimeout( doPrint, MAX_PRINT_TIMEOUT );
			lazyImageLoader.loadImages( lazyImageLoader.queryPlaceholders( document.getElementById( 'content' ) ) )
				.then( doPrintBeforeTimeout, doPrintBeforeTimeout );
		}
	}

	/**
	 * Generate a download icon for triggering print functionality if
	 * printing is available.
	 * Calling this method has side effects:
	 * It calls mw.util.addPortletLink and may inject an element into the page.
	 *
	 * @param {Page} page
	 * @param {number[]} supportedNamespaces
	 * @param {Window} [windowObj] window object
	 * @param {boolean} [overflowList] Append to overflow list
	 * @return {jQuery.Object|null}
	 */
	function downloadPageAction( page, supportedNamespaces, windowObj, overflowList ) {
		var
			portletLink, iconElement,
			modifier = overflowList ? 'toggle-list-item__anchor toggle-list-item__label' :
				'mw-ui-icon-element mw-ui-icon-with-label-desktop',
			spinner = icons.spinner( {
				modifier: modifier
			} );

		if (
			isAvailable(
				windowObj, page, navigator.userAgent,
				supportedNamespaces
			)
		) {

			portletLink = mw.util.addPortletLink(
				overflowList ? 'page-actions-overflow' : 'page-actions',
				'#',
				mw.msg( 'minerva-download' ),
				// id
				'minerva-download',
				// tooltip
				mw.msg( 'minerva-download' ),
				// access key
				'p',
				overflowList ? null : document.getElementById( 'page-actions-watch' )
			);
			if ( portletLink ) {
				portletLink.addEventListener( 'click', function () {
					onClick( portletLink, spinner );
				} );
				spinner.$el.hide().insertAfter(
					$( portletLink ).find( '.mw-ui-icon' )
				);
				iconElement = portletLink.querySelector( '.mw-ui-icon' );
				if ( iconElement ) {
					iconElement.classList.add( 'mw-ui-icon-minerva-download' );
				}
			}
			return portletLink;
		} else {
			return null;
		}
	}

	module.exports = {
		downloadPageAction: downloadPageAction,
		test: {
			isAvailable: isAvailable,
			onClick: onClick
		}
	};

// eslint-disable-next-line no-restricted-properties
}( mw.mobileFrontend, mw.track ) );
