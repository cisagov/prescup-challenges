'use strict';

const assert = require( 'assert' );
const { ArticlePage } = require( '../support/world.js' );

const iSeeALinkToAboutPage = () => {
	assert.strictEqual( ArticlePage.menu_element.$( '*=About' ).isDisplayed(), true );
};

const iClickOnTheMainNavigationButton = () => {
	ArticlePage.menu_button_element.waitForDisplayed();
	ArticlePage.menu_button_element.click();
};

const iShouldSeeAUserPageLinkInMenu = () => {
	ArticlePage.menu_element.$( '.menu__item--user' );
};

const iShouldSeeLogoutLinkInMenu = () => {
	ArticlePage.menu_element.$( '.menu__item--logout' );
};

const iShouldSeeALinkInMenu = ( text ) => {
	assert.strictEqual( ArticlePage.menu_element.$( `span=${text}` ).isDisplayed(),
		true, `Link to ${text} is visible.` );
};

const iShouldSeeALinkToDisclaimer = () => {
	ArticlePage.menu_element.$( 'span=Disclaimers' ).waitForDisplayed();
	assert.strictEqual( ArticlePage.menu_element.$( 'span=Disclaimers' ).isDisplayed(), true );
};

module.exports = {
	iClickOnTheMainNavigationButton,
	iSeeALinkToAboutPage, iShouldSeeAUserPageLinkInMenu,
	iShouldSeeLogoutLinkInMenu,
	iShouldSeeALinkInMenu, iShouldSeeALinkToDisclaimer
};
