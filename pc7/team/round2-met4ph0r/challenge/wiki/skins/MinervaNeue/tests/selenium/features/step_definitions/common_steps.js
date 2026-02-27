'use strict';

const assert = require( 'assert' ),
	MWBot = require( 'mwbot' ),
	Api = require( 'wdio-mediawiki/Api' ),
	ArticlePageWithOverlay = require( '../support/pages/article_page_with_overlay' ),
	{ ArticlePage, UserLoginPage } = require( '../support/world.js' );

const waitForPropagation = ( timeMs ) => {
	// wait 2 seconds so the change can propogate.
	// Replace this with a more dynamic statement.
	// eslint-disable-next-line wdio/no-pause
	browser.pause( timeMs );
};

const createPages = ( pages ) => {
	const summary = 'edit by selenium test';
	browser.call( () => {
		const bot = new MWBot();
		return bot.loginGetEditToken( {
			username: browser.options.username,
			password: browser.options.password,
			apiUrl: `${browser.options.baseUrl}/api.php`
		} )
			.then( () => {
				return bot.batch(
					pages.map( ( page ) => [ 'create' ].concat( page ).concat( [ summary ] ) )
				).catch( ( err ) => {
					if ( err.code === 'articleexists' ) {
						return;
					}
					throw err;
				} );
			} )
			.catch( ( err ) => { throw err; } );
	} );
};

const createPage = ( title, wikitext ) => {
	browser.call( async () => {
		const bot = await Api.bot();
		await bot.edit( title, wikitext );
	} );
};

const iAmUsingTheMobileSite = () => {
	ArticlePage.setMobileMode();
};

const iAmInBetaMode = () => {
	ArticlePage.setBetaMode();
};

const iAmOnPage = ( article ) => {
	ArticlePage.open( article );
	// Make sure the article opened and JS loaded.
	ArticlePage.waitUntilResourceLoaderModuleReady( 'skins.minerva.scripts' );
};

const iAmLoggedIn = () => {
	UserLoginPage.open();
	UserLoginPage.loginAdmin();
	assert.strictEqual( ArticlePage.is_authenticated_element.isExisting(), true );
};

const iAmLoggedIntoTheMobileWebsite = () => {
	iAmUsingTheMobileSite();
	iAmLoggedIn();
};

const pageExists = ( title ) => {
	browser.call( () =>
		createPage( title, 'Page created by Selenium browser test.' )
	);
	// wait 2 seconds so the change can propogate.
	waitForPropagation( 2000 );
};

const pageExistsWithText = ( title, text ) => {
	browser.call( () =>
		createPage( title, text )
	);
	// wait 2 seconds so the change can propogate.
	waitForPropagation( 2000 );
};

const iAmOnAPageThatDoesNotExist = () => {
	return iAmOnPage( `NewPage ${new Date()}` );
};

const iShouldSeeAToastNotification = () => {
	ArticlePage.notification_element.waitForDisplayed();
};

const iShouldSeeAToastNotificationWithMessage = ( msg ) => {
	iShouldSeeAToastNotification();
	const notificationBody = ArticlePage.notification_element.$( '.mw-notification-content' );
	assert.strictEqual( notificationBody.getText().includes( msg ), true );
};

const iClickTheBrowserBackButton = () => {
	browser.back();
};

const iClickTheOverlayCloseButton = () => {
	waitForPropagation( 2000 );
	ArticlePageWithOverlay.overlay_close_element.waitForDisplayed();
	ArticlePageWithOverlay.overlay_close_element.click();
};

const iSeeAnOverlay = () => {
	ArticlePageWithOverlay.overlay_element.waitForDisplayed();
	assert.strictEqual( ArticlePageWithOverlay.overlay_element.isDisplayed(), true );
};

const iDoNotSeeAnOverlay = () => {
	waitForPropagation( 5000 );
	browser.waitUntil( () => !ArticlePageWithOverlay.overlay_element.isDisplayed() );
	assert.strictEqual( ArticlePageWithOverlay.overlay_element.isDisplayed(), false );
};

const iAmUsingMobileScreenResolution = () => {
	browser.setWindowSize( 320, 480 );
};

module.exports = {
	waitForPropagation,
	iAmUsingMobileScreenResolution,
	iSeeAnOverlay, iDoNotSeeAnOverlay,
	iClickTheOverlayCloseButton,
	iClickTheBrowserBackButton,
	createPage, createPages,
	pageExistsWithText,
	pageExists, iAmOnAPageThatDoesNotExist, iShouldSeeAToastNotification,
	iShouldSeeAToastNotificationWithMessage,
	iAmLoggedIntoTheMobileWebsite,
	iAmUsingTheMobileSite,
	iAmLoggedIn, iAmOnPage, iAmInBetaMode
};
