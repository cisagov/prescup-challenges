'use strict';

const assert = require( 'assert' );
const { ArticlePage } = require( '../support/world.js' );
const { iAmOnPage } = require( './common_steps' );
const { theTextOfTheFirstHeadingShouldBe } = require( './editor_steps' );

const username = browser.config.mwUser.replace( /_/g, ' ' );

const iVisitMyUserPage = () => {
	iAmOnPage( `User:${username}` );
};

const iShouldBeOnMyUserPage = () => {
	theTextOfTheFirstHeadingShouldBe( username );
};

const thereShouldBeALinkToMyContributions = () => {
	assert.strictEqual( ArticlePage.contributions_link_element.isDisplayed(), true );
};
const thereShouldBeALinkToMyTalkPage = () => {
	assert.strictEqual( ArticlePage.talk_tab_element.isDisplayed(), true );
};

module.exports = { iVisitMyUserPage, iShouldBeOnMyUserPage,
	thereShouldBeALinkToMyContributions, thereShouldBeALinkToMyTalkPage };
