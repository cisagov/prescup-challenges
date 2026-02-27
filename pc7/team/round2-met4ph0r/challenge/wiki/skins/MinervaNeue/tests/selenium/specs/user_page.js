'use strict';

const { iAmUsingTheMobileSite } = require( '../features/step_definitions/common_steps' ),
	{ iVisitMyUserPage, iShouldBeOnMyUserPage,
		thereShouldBeALinkToMyContributions, thereShouldBeALinkToMyTalkPage
	} = require( '../features/step_definitions/user_page_steps' );

// @chrome @firefox @login @test2.m.wikipedia.org @vagrant
describe( 'User:<username>', () => {

	beforeEach( () => {
		iAmUsingTheMobileSite();
		iVisitMyUserPage();
	} );

	// </username>@en.m.wikipedia.beta.wmflabs.org
	it( 'Check components in user page', () => {
		iShouldBeOnMyUserPage();
		thereShouldBeALinkToMyTalkPage();
		thereShouldBeALinkToMyContributions();
	} );
} );
