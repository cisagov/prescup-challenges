'use strict';

const { iAmViewingAnUnwatchedPage } = require( '../features/step_definitions/create_page_api_steps' ),
	{
		iShouldSeeAToastNotificationWithMessage,
		iAmLoggedIntoTheMobileWebsite
	} = require( '../features/step_definitions/common_steps' ),
	{
		theWatchstarShouldBeSelected,
		iClickTheWatchstar } = require( '../features/step_definitions/watch_steps' );

// @chrome @smoke @test2.m.wikipedia.org @login @vagrant
describe( 'Manage Watchlist', () => {

	beforeEach( () => {
		iAmLoggedIntoTheMobileWebsite();
	} );

	it( 'Add an article to the watchlist', () => {
		iAmViewingAnUnwatchedPage();
		iClickTheWatchstar();
		iShouldSeeAToastNotificationWithMessage( 'added' );
		theWatchstarShouldBeSelected();
	} );
} );
