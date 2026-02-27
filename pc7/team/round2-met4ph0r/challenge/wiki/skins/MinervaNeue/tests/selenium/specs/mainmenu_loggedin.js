'use strict';

const {
		iAmLoggedIntoTheMobileWebsite,
		iAmOnPage
	} = require( '../features/step_definitions/common_steps' ),
	{ iSeeALinkToAboutPage, iShouldSeeAUserPageLinkInMenu,
		iShouldSeeLogoutLinkInMenu,
		iClickOnTheMainNavigationButton,
		iShouldSeeALinkInMenu, iShouldSeeALinkToDisclaimer
	} = require( '../features/step_definitions/menu_steps' );

// @chrome @en.m.wikipedia.beta.wmflabs.org @firefox @test2.m.wikipedia.org @vagrant @login
describe( 'Menus open correct page for anonymous users', () => {

	beforeEach( () => {
		iAmLoggedIntoTheMobileWebsite();
		iAmOnPage( 'Main Page' );
	} );

	it( 'Check links in menu', () => {
		iClickOnTheMainNavigationButton();
		iShouldSeeALinkToDisclaimer();
		iShouldSeeAUserPageLinkInMenu();
		iSeeALinkToAboutPage();
		[ 'Home', 'Random', 'Settings', 'Contributions',
			'Watchlist' ].forEach( ( label ) => {
			iShouldSeeALinkInMenu( label );
		} );
		iShouldSeeLogoutLinkInMenu();
		try {
			iShouldSeeALinkInMenu( 'Nearby' );
		} catch ( e ) {
			console.warn( 'Nearby item will only appear in main menu if $wgMFNearby is configured' );
		}
	} );
} );
