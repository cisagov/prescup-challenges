/**
 * JavaScript enhancement to persist the sidebar state for logged-in users.
 *
 */

/** @interface MwApi */

var /** @type {MwApi} */api,
	SIDEBAR_BUTTON_ID = 'mw-sidebar-button',
	debounce = require( /** @type {string} */ ( 'mediawiki.util' ) ).debounce,
	SIDEBAR_CHECKBOX_ID = 'mw-sidebar-checkbox',
	SIDEBAR_PREFERENCE_NAME = 'VectorSidebarVisible';

/**
 * Execute a debounced API request to save the sidebar user preference.
 * The request is meant to fire 1000 milliseconds after the last click on
 * the sidebar button.
 *
 * @param {HTMLInputElement} checkbox
 * @return {any}
 */
function saveSidebarState( checkbox ) {
	return debounce( function () {
		api = api || new mw.Api();
		api.saveOption( SIDEBAR_PREFERENCE_NAME, checkbox.checked ? 1 : 0 );

		// Trigger a resize event so other parts of the page can adapt:
		var event;
		if ( typeof Event === 'function' ) {
			event = new Event( 'resize' );
		} else {
			// IE11
			event = window.document.createEvent( 'UIEvents' );
			event.initUIEvent( 'resize', true, false, window, 0 );
		}
		window.dispatchEvent( event );
	}, 1000 );
}

/**
 * Bind the event handler that saves the sidebar state to the click event
 * on the sidebar button.
 *
 * @param {HTMLElement|null} checkbox
 * @param {HTMLElement|null} button
 */
function bindSidebarClickEvent( checkbox, button ) {
	if ( checkbox instanceof HTMLInputElement && button ) {
		checkbox.addEventListener( 'input', saveSidebarState( checkbox ) );
	}
}

function init() {
	var checkbox = window.document.getElementById( SIDEBAR_CHECKBOX_ID ),
		button = window.document.getElementById( SIDEBAR_BUTTON_ID );

	if ( mw.config.get( 'wgUserName' ) && !mw.config.get( 'wgVectorDisableSidebarPersistence' ) ) {
		bindSidebarClickEvent( checkbox, button );
	}
}

module.exports = {
	init: init
};
