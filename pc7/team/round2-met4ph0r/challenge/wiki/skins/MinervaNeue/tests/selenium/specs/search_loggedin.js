'use strict';

const {
		pageExists, iShouldSeeAToastNotification,
		iAmUsingMobileScreenResolution,
		iAmUsingTheMobileSite,
		iAmLoggedIntoTheMobileWebsite,
		iAmOnPage
	} = require( '../features/step_definitions/common_steps' ),
	{
		iClickTheSearchIcon,
		iTypeIntoTheSearchBox,
		iClickASearchWatchstar,
		iSeeTheSearchOverlay
	} = require( '../features/step_definitions/search_steps' );

// @test2.m.wikipedia.org @vagrant @login
describe( 'Search', () => {
	it( 'Clicking on a watchstar toggles the watchstar', () => {
		iAmUsingTheMobileSite();
		pageExists( 'Selenium search test' );
		iAmLoggedIntoTheMobileWebsite();
		iAmOnPage( 'Main Page' );
		iAmUsingMobileScreenResolution();
		iClickTheSearchIcon();
		iSeeTheSearchOverlay();
		iTypeIntoTheSearchBox( 'Selenium search tes' );
		// This pause statement is a temporary bandaid until we figure a bettery dynamic sync
		// eslint-disable-next-line wdio/no-pause
		browser.pause( 1000 );
		iClickASearchWatchstar();
		iShouldSeeAToastNotification();
	} );
} );
