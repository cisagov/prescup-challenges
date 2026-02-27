// eslint-disable-next-line no-restricted-properties
var mobile = mw.mobileFrontend.require( 'mobile.startup' ),
	drawers = require( './drawers.js' ),
	CtaDrawer = mobile.CtaDrawer,
	Button = mobile.Button,
	Anchor = mobile.Anchor;

/**
 * Initialize red links call-to-action
 *
 * Upon clicking a red link, show an interstitial CTA explaining that the page doesn't exist
 * with a button to create it, rather than directly navigate to the edit form.
 *
 * Special case T201339: following a red link to a user or user talk page should not prompt for
 * its creation. The reasoning is that user pages should be created by their owners and it's far
 * more common that non-owners follow a user's red linked user page to consider their
 * contributions, account age, or other activity.
 *
 * For example, a user adds a section to a Talk page and signs their contribution (which creates
 * a link to their user page whether exists or not). If the user page does not exist, that link
 * will be red. In both cases, another user follows this link, not to edit create a page for
 * that user but to obtain information on them.
 *
 * @ignore
 * @param {jQuery.Object} $redLinks
 */
function initRedlinksCta( $redLinks ) {
	$redLinks.on( 'click', function ( ev ) {
		var drawerOptions = {
				progressiveButton: new Button( {
					progressive: true,
					label: mw.msg( 'mobile-frontend-editor-redlink-create' ),
					href: $( this ).attr( 'href' )
				} ).options,
				actionAnchor: new Anchor( {
					progressive: true,
					label: mw.msg( 'mobile-frontend-editor-redlink-leave' ),
					additionalClassNames: 'cancel'
				} ).options,
				onBeforeHide: drawers.discardDrawer,
				content: mw.msg( 'mobile-frontend-editor-redlink-explain' )
			},
			drawer = CtaDrawer( drawerOptions );

		// use preventDefault() and not return false to close other open
		// drawers or anything else.
		ev.preventDefault();
		ev.stopPropagation();
		drawers.displayDrawer( drawer, { hideOnScroll: true } );
	} );
}

/**
 * A CtaDrawer should show for anonymous users.
 *
 * @param {jQuery.Object} $watchstar
 */
function initWatchstarCta( $watchstar ) {
	var watchCtaDrawer;
	// show a CTA for anonymous users
	$watchstar.on( 'click', function ( ev ) {
		if ( !watchCtaDrawer ) {
			watchCtaDrawer = CtaDrawer( {
				content: mw.msg( 'minerva-watchlist-cta' ),
				queryParams: {
					warning: 'mobile-frontend-watchlist-purpose',
					campaign: 'mobile_watchPageActionCta',
					returntoquery: 'article_action=watch'
				},
				onBeforeHide: drawers.discardDrawer,
				signupQueryParams: {
					warning: 'mobile-frontend-watchlist-signup-action'
				}
			} );
		}
		// If it's already shown dont display again
		// (if user is clicking fast since we are reusing the drawer
		// this might result in the drawer opening and closing)
		if ( !watchCtaDrawer.$el[ 0 ].parentNode ) {
			drawers.displayDrawer( watchCtaDrawer, { hideOnScroll: true } );
		}
		// prevent default to stop the user
		// being navigated to Special:UserLogin
		ev.preventDefault();
		// Don't stopProgation, as we want WikimediaEvents to log clicks to this.
	} );
}

module.exports = {
	initWatchstarCta: initWatchstarCta,
	initRedlinksCta: initRedlinksCta
};
