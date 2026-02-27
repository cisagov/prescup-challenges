'use strict';

const { iSeeAnOverlay } = require( './common_steps' );
const { ArticlePage } = require( '../support/world.js' );
const ArticlePageWithOverlay = require( '../support/pages/article_page_with_overlay' );

const iClickTheSearchIcon = () => {
	ArticlePage.search_icon_element.waitForDisplayed();
	ArticlePage.search_icon_element.click();
};

const iTypeIntoTheSearchBox = ( term ) => {
	const input = ArticlePageWithOverlay.overlay_element
		.$( 'input' );
	input.waitForExist();
	input.setValue( term );
};

const iSeeSearchResults = () => {
	ArticlePageWithOverlay.overlay_element
		.$( '.page-list' ).waitForExist( 5000 );
};

const iClickASearchWatchstar = () => {
	iSeeSearchResults();
	const watchThisArticle = ArticlePageWithOverlay.overlay_element
		.$( '.watch-this-article' );
	watchThisArticle.waitForExist( 5000 );
	watchThisArticle.click();
};

const iSeeTheSearchOverlay = () => {
	iSeeAnOverlay();
};

module.exports = {
	iClickTheSearchIcon,
	iTypeIntoTheSearchBox,
	iClickASearchWatchstar,
	iSeeTheSearchOverlay
};
