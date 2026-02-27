'use strict';

const {
		iAmOnAPageThatDoesNotExist,
		iAmLoggedIntoTheMobileWebsite
	} = require( './../features/step_definitions/common_steps' ),
	{
		iClickTheEditButton, iSeeTheWikitextEditorOverlay, iClearTheEditor,
		iDoNotSeeTheWikitextEditorOverlay,
		iTypeIntoTheEditor, iClickContinue, iClickSubmit, iSayOkayInTheConfirmDialog,
		thereShouldBeARedLinkWithText
	} = require( './../features/step_definitions/editor_steps' );

// @test2.m.wikipedia.org @login
describe( 'Wikitext Editor (Makes actual saves)', () => {

	beforeEach( () => {
		iAmLoggedIntoTheMobileWebsite();
	} );

	// @editing @en.m.wikipedia.beta.wmflabs.org
	it.skip( 'Broken redirects', () => {
		iAmOnAPageThatDoesNotExist();
		iClickTheEditButton();
		iSeeTheWikitextEditorOverlay();
		iClearTheEditor();
		iTypeIntoTheEditor( '#REDIRECT [[AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA]]' );
		iClickContinue();
		iClickSubmit();
		iSayOkayInTheConfirmDialog();
		iDoNotSeeTheWikitextEditorOverlay();
		thereShouldBeARedLinkWithText( 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' );
	} );
} );
