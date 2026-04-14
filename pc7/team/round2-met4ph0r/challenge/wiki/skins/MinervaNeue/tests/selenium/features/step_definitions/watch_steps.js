'use strict';

const assert = require( 'assert' );
const { ArticlePage } = require( '../support/world.js' );

const theWatchstarShouldNotBeSelected = () => {
	ArticlePage.watch_element.waitForExist();
	assert.strictEqual( ArticlePage.watched_element.isExisting(), false,
		'the watched element should not be present' );
};

const theWatchstarShouldBeSelected = () => {
	ArticlePage.watched_element.waitForExist();
	const watchstar = ArticlePage.watched_element;
	assert.strictEqual( watchstar.isDisplayed(), true );
};

const iClickTheWatchstar = () => {
	ArticlePage.waitUntilResourceLoaderModuleReady( 'skins.minerva.scripts' );
	ArticlePage.watch_element.waitForExist();
	ArticlePage.watch_element.click();
};

const iClickTheUnwatchStar = () => {
	ArticlePage.waitUntilResourceLoaderModuleReady( 'skins.minerva.scripts' );
	ArticlePage.watched_element.waitForExist();
	ArticlePage.watched_element.click();
};

module.exports = {
	theWatchstarShouldNotBeSelected, theWatchstarShouldBeSelected,
	iClickTheWatchstar, iClickTheUnwatchStar };
