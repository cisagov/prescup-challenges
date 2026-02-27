/**
 * Initialise code that requires MobileFrontend.
 *
 * @todo anything that doesn't require MobileFrontend should be moved into ./setup.js
 * @todo anything that can be rewritten without MobileFrontend (possibly using new frontend
 * framework or upstreamed from MobileFrotend to core) should be and moved into ./setup.js
 * @todo anything left should be moved to MobileFrontend extension and removed from here.
 */
var HISTORY_ICON_CLASS = 'mw-ui-icon-wikimedia-history-base20';
var HISTORY_ARROW_CLASS = 'mw-ui-icon-mf-expand-gray';
module.exports = function () {
	var
		// eslint-disable-next-line no-restricted-properties
		mobile = mw.mobileFrontend.require( 'mobile.startup' ),
		PageGateway = mobile.PageGateway,
		LanguageInfo = mobile.LanguageInfo,
		permissions = mw.config.get( 'wgMinervaPermissions' ) || {},
		toast = mobile.toast,
		Icon = mobile.Icon,
		time = mobile.time,
		preInit = require( './preInit.js' ),
		mobileRedirect = require( './mobileRedirect.js' ),
		search = require( './search.js' ),
		references = require( './references.js' ),
		TitleUtil = require( './TitleUtil.js' ),
		issues = require( './page-issues/index.js' ),
		Toolbar = require( './Toolbar.js' ),
		ToggleList = require( '../../includes/Skins/ToggleList/ToggleList.js' ),
		TabScroll = require( './TabScroll.js' ),
		router = require( 'mediawiki.router' ),
		ctaDrawers = require( './ctaDrawers.js' ),
		drawers = require( './drawers.js' ),
		desktopMMV = mw.loader.getState( 'mmv.bootstrap' ),
		overlayManager = mobile.OverlayManager.getSingleton(),
		currentPage = mobile.currentPage(),
		currentPageHTMLParser = mobile.currentPageHTMLParser(),
		$redLinks = currentPageHTMLParser.getRedLinks(),
		api = new mw.Api(),
		eventBus = mobile.eventBusSingleton,
		namespaceIDs = mw.config.get( 'wgNamespaceIds' );

	/**
	 * Event handler for clicking on an image thumbnail
	 *
	 * @param {jQuery.Event} ev
	 * @ignore
	 */
	function onClickImage( ev ) {
		// Do not interfere with non-left clicks or if modifier keys are pressed.
		if ( ( ev.button !== 0 && ev.which !== 1 ) ||
			ev.altKey || ev.ctrlKey || ev.shiftKey || ev.metaKey ) {
			return;
		}

		ev.preventDefault();
		routeThumbnail( $( this ).data( 'thumb' ) );
	}

	/**
	 * @param {jQuery.Element} thumbnail
	 * @ignore
	 */
	function routeThumbnail( thumbnail ) {
		router.navigate( '#/media/' + encodeURIComponent( thumbnail.getFileName() ) );
	}

	/**
	 * Add routes to images and handle clicks
	 *
	 * @method
	 * @ignore
	 * @param {jQuery.Object} [$container] Optional container to search within
	 */
	function initMediaViewer( $container ) {
		currentPageHTMLParser.getThumbnails( $container ).forEach( function ( thumb ) {
			thumb.$el.off().data( 'thumb', thumb ).on( 'click', onClickImage );
		} );
	}

	/**
	 * Hijack the Special:Languages link and replace it with a trigger to a languageOverlay
	 * that displays the same data
	 *
	 * @ignore
	 */
	function initButton() {
		// This catches language selectors in page actions and in secondary actions (e.g. Main Page)
		// eslint-disable-next-line no-jquery/no-global-selector
		var $primaryBtn = $( '.language-selector' );

		if ( $primaryBtn.length ) {
			// We only bind the click event to the first language switcher in page
			$primaryBtn.on( 'click', function ( ev ) {
				ev.preventDefault();

				if ( $primaryBtn.attr( 'href' ) || $primaryBtn.find( 'a' ).length ) {
					router.navigate( '/languages' );
				} else {
					mw.notify( mw.msg( 'mobile-frontend-languages-not-available' ) );
				}
			} );
		}
	}

	/**
	 * Returns a rejected promise if MultimediaViewer is available. Otherwise
	 * returns the mediaViewerOverlay
	 *
	 * @method
	 * @ignore
	 * @param {string} title the title of the image
	 * @return {void|Overlay} note must return void if the overlay should not show (see T262703)
	 *  otherwise an Overlay is expected and this can lead to e.on/off is not a function
	 */
	function makeMediaViewerOverlayIfNeeded( title ) {
		if ( mw.loader.getState( 'mmv.bootstrap' ) === 'ready' ) {
			// This means MultimediaViewer has been installed and is loaded.
			// Avoid loading it (T169622)
			return;
		}
		try {
			title = decodeURIComponent( title );
		} catch ( e ) {
			// e.g. https://ro.m.wikipedia.org/wiki/Elisabeta_I_a_Angliei#/media/Fi%C8%18ier:Elizabeth_I_Rainbow_Portrait.jpg
			return;
		}

		return mobile.mediaViewer.overlay( {
			api: api,
			thumbnails: currentPageHTMLParser.getThumbnails(),
			title: title,
			eventBus: eventBus
		} );
	}

	// Routes
	overlayManager.add( /^\/media\/(.+)$/, makeMediaViewerOverlayIfNeeded );
	overlayManager.add( /^\/languages$/, function () {
		return mobile.languageOverlay( new PageGateway( api ) );
	} );
	// Register a LanguageInfo overlay which has no built-in functionality;
	// a hook is fired when a language is selected, and extensions can respond
	// to that hook. See GrowthExperiments WelcomeSurvey feature (in gerrit
	// Ib558dc7c46cc56ff667957f9126bbe0471d25b8e for example usage).
	overlayManager.add( /^\/languages\/all$/, function () {
		return mobile.languageInfoOverlay( new LanguageInfo( api ), true );
	} );
	overlayManager.add( /^\/languages\/all\/no-suggestions$/, function () {
		return mobile.languageInfoOverlay( new LanguageInfo( api ), false );
	} );

	// Setup
	$( function () {
		initButton();
	} );

	// If the MMV module is missing or disabled from the page, initialise our version
	if ( desktopMMV === null || desktopMMV === 'registered' ) {
		mw.hook( 'wikipage.content' ).add( initMediaViewer );
	}

	/**
	 * Initialisation function for last modified module.
	 *
	 * Enhances an element representing a time
	 * to show a human friendly date in seconds, minutes, hours, days
	 * months or years
	 *
	 * @ignore
	 * @param {jQuery.Object} $lastModifiedLink
	 */
	function initHistoryLink( $lastModifiedLink ) {
		var delta, $msg, $bar,
			ts, username, gender;

		ts = $lastModifiedLink.data( 'timestamp' );
		username = $lastModifiedLink.data( 'user-name' ) || false;
		gender = $lastModifiedLink.data( 'user-gender' );

		if ( ts ) {
			delta = time.getTimeAgoDelta( parseInt( ts, 10 ) );
			if ( time.isRecent( delta ) ) {
				$bar = $lastModifiedLink.closest( '.last-modified-bar' );
				$bar.addClass( 'active' );
				$bar.find( '.' + HISTORY_ICON_CLASS )
					.addClass( HISTORY_ICON_CLASS.replace( '-base20', '-invert' ) )
					.removeClass( HISTORY_ICON_CLASS );
				$bar.find( '.' + HISTORY_ARROW_CLASS )
					.addClass( HISTORY_ARROW_CLASS.replace( '-gray', '-invert' ) )
					.removeClass( HISTORY_ARROW_CLASS );
			}

			$msg = $( '<span>' )
				// The new element should maintain the non-js element's CSS classes.
				.attr( 'class', $lastModifiedLink.attr( 'class' ) )
				.html(
					time.getLastModifiedMessage( ts, username, gender,
						// For cached HTML
						$lastModifiedLink.attr( 'href' )
					)
				);
			$lastModifiedLink.replaceWith( $msg );
		}
	}

	/**
	 * @method
	 * @param {jQuery.Event} ev
	 */
	function amcHistoryClickHandler( ev ) {
		var
			self = this,
			amcOutreach = mobile.amcOutreach,
			amcCampaign = amcOutreach.loadCampaign(),
			onDismiss = function () {
				toast.showOnPageReload( mw.msg( 'mobile-frontend-amc-outreach-dismissed-message' ) );
				window.location = self.href;
			},
			drawer = amcCampaign.showIfEligible( amcOutreach.ACTIONS.onHistoryLink, onDismiss, currentPage.title, 'action=history' );

		if ( drawer ) {
			ev.preventDefault();
			// stopPropagation is needed to prevent drawer from immediately closing
			// when shown (drawers.js adds a click event to window when drawer is
			// shown
			ev.stopPropagation();

			drawers.displayDrawer( drawer, {} );
			drawers.lockScroll();
		}
	}

	/**
	 * @method
	 * @param {jQuery.Object} $lastModifiedLink
	 * @ignore
	 */
	function initAmcHistoryLink( $lastModifiedLink ) {
		$lastModifiedLink.one( 'click', amcHistoryClickHandler );
	}

	/**
	 * Initialisation function for last modified times
	 *
	 * Enhances .modified-enhancement element
	 * to show a human friendly date in seconds, minutes, hours, days
	 * months or years
	 *
	 * @ignore
	 */
	function initModifiedInfo() {
		// eslint-disable-next-line no-jquery/no-global-selector
		$( '.modified-enhancement' ).each( function () {
			initHistoryLink( $( this ) );
		} );
	}

	/**
	 * Initialisation function for user creation module.
	 *
	 * Enhances an element representing a time
	 * to show a human friendly date in seconds, minutes, hours, days
	 * months or years
	 *
	 * @ignore
	 * @param {jQuery.Object} [$tagline]
	 */
	function initRegistrationDate( $tagline ) {
		var msg, ts;

		ts = $tagline.data( 'userpage-registration-date' );

		if ( ts ) {
			msg = time.getRegistrationMessage( ts, $tagline.data( 'userpage-gender' ) );
			$tagline.text( msg );
		}
	}

	/**
	 * Initialisation function for registration date on user page
	 *
	 * Enhances .tagline-userpage element
	 * to show human friendly date in seconds, minutes, hours, days
	 * months or years
	 *
	 * @ignore
	 */
	function initRegistrationInfo() {
		// eslint-disable-next-line no-jquery/no-global-selector
		$( '#tagline-userpage' ).each( function () {
			initRegistrationDate( $( this ) );
		} );
	}

	/**
	 * Tests a URL to determine if it links to a local User namespace page or not.
	 *
	 * Assuming the current page visited is hosted on metawiki, the following examples would return
	 * true:
	 *
	 *   https://meta.wikimedia.org/wiki/User:Foo
	 *   /wiki/User:Foo
	 *   /wiki/User:Nonexistent_user_page
	 *
	 * The following examples return false:
	 *
	 *   https://en.wikipedia.org/wiki/User:Foo
	 *   /wiki/Foo
	 *   /wiki/User_talk:Foo
	 *
	 * @param {string} url
	 * @return {boolean}
	 */
	function isUserUri( url ) {
		var
			title = TitleUtil.newFromUri( url ),
			namespace = title ? title.getNamespaceId() : undefined;
		return namespace === namespaceIDs.user;
	}

	/**
	 * Strip the edit action from red links to nonexistent User namespace pages.
	 *
	 * @return {void}
	 */
	function initUserRedLinks() {
		$redLinks.filter( function ( _, element ) {
			// Filter out non-User namespace pages.
			return isUserUri( element.href );
		} ).each( function ( _, element ) {
			var uri = new mw.Uri( element.href );
			if ( uri.query.action !== 'edit' ) {
				// Nothing to strip.
				return;
			}

			// Strip the action.
			delete uri.query.action;

			// Update the element with the new link.
			element.href = uri.toString();
		} );
	}

	$( function () {
		var
			// eslint-disable-next-line no-jquery/no-global-selector
			$watch = $( '#page-actions-watch' ),
			toolbarElement = document.querySelector( Toolbar.selector ),
			userMenu = document.querySelector( '.minerva-user-menu' ), // See UserMenuDirector.
			navigationDrawer = document.querySelector( '.navigation-drawer' );

		// The `minerva-animations-ready` class can be used by clients to prevent unwanted
		// CSS transitions from firing on page load in some browsers (see
		// https://bugs.chromium.org/p/chromium/issues/detail?id=332189 as well as
		// https://phabricator.wikimedia.org/T234570#5779890). Since JS adds this
		// class after the CSS transitions loads, this issue is circumvented. See
		// MainMenu.less for an example of how this is used.
		$( document.body ).addClass( 'minerva-animations-ready' );

		// eslint-disable-next-line no-jquery/no-global-selector
		$( '.mw-mf-page-center__mask' ).on( 'click', function ( ev ) {
			var path = router.getPath();
			// avoid jumping to the top of the page and polluting history by avoiding the
			// resetting of the hash unless the hash is being utilised (T237015).
			if ( !path ) {
				ev.preventDefault();
			}
		} );
		// Init:
		// - main menu closes when you click outside of it
		// - redirects show a toast.
		preInit();
		// - references
		references();
		// - search
		search();
		// - mobile redirect
		mobileRedirect( mobile.amcOutreach, currentPage );

		// Enhance timestamps on last-modified bar and watchlist
		// to show relative time.
		initModifiedInfo();
		initRegistrationInfo();
		// eslint-disable-next-line no-jquery/no-global-selector
		initAmcHistoryLink( $( '.last-modified-bar__text a' ) );

		if ( toolbarElement ) {
			Toolbar.bind( window, toolbarElement );
			// Update the edit icon and add a download icon.
			Toolbar.render( window, toolbarElement );
		}
		if ( userMenu ) {
			ToggleList.bind( window, userMenu );
		}
		if ( navigationDrawer ) {
			ToggleList.bind( window, navigationDrawer );
			var navigationDrawerMask = navigationDrawer.querySelector( '.main-menu-mask' );
			// The 'for' attribute is used to close the drawer when the mask is clicked without JS
			// Since we are using JS to enhance the drawer behavior, we need to
			// remove the attribute to prevent the drawer from being toggled twice
			navigationDrawerMask.removeAttribute( 'for' );
		}
		TabScroll.initTabsScrollPosition();
		// Setup the issues banner on the page
		// Pages which dont exist (id 0) cannot have issues
		if ( !currentPage.isMissing ) {
			issues.init( overlayManager, currentPageHTMLParser );
		}

		// deprecation notices
		mw.log.deprecate( router, 'navigate', router.navigate, 'use navigateTo instead' );

		// If MobileFrontend installed we add a table of contents icon to the table of contents.
		// This should probably be done in the parser.
		// setup toc icons
		mw.hook( 'wikipage.content' ).add( function ( $container ) {
			var $toctitle = $container.find( '.toctitle' );
			new Icon( {
				glyphPrefix: 'minerva',
				name: 'listBullet'
			} ).$el.prependTo( $toctitle );
			new Icon( {
				glyphPrefix: 'mf',
				name: 'expand',
				isSmall: true
			} ).$el.appendTo( $toctitle );
		} );

		// wire up talk icon if necessary
		if ( permissions.talk ) {
			require( './talk.js' )( mobile );
		}

		// wire up watch icon if necessary
		if ( permissions.watch && mw.user.isAnon() ) {
			ctaDrawers.initWatchstarCta( $watch );
		}
		ctaDrawers.initRedlinksCta(
			$redLinks.filter( function ( _, element ) {
				// Filter out local User namespace pages.
				return !isUserUri( element.href );
			} )
		);
		initUserRedLinks();
	} );
};
