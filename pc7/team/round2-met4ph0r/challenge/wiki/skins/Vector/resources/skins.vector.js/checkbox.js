/**
 * JavaScript enhancement for Vector specific checkbox hacks
 *
 * Most checkbox hacks use core JS for progressive enhancements (i.e. dropdownMenus.js),
 * However the main menu and collapsible TOC use a variation of the checkbox hack
 * that requires their own JS for enhancements.
 *
 */

/** @interface MwApiConstructor */
/** @interface CheckboxHack */

var checkboxHack = /** @type {CheckboxHack} */ require( /** @type {string} */( 'mediawiki.page.ready' ) ).checkboxHack;

/**
 * Revise the button's `aria-expanded` state to match the checked state.
 *
 * @param {HTMLInputElement} checkbox
 * @param {HTMLElement} button
 * @return {void}
 * @ignore
 */
function updateAriaExpanded( checkbox, button ) {
	button.setAttribute( 'aria-expanded', checkbox.checked.toString() );
}

/**
 * Update the `aria-expanded` attribute based on checkbox state (target visibility) changes.
 *
 * @param {HTMLInputElement} checkbox
 * @param {HTMLElement} button
 * @return {function(): void} Cleanup function that removes the added event listeners.
 * @ignore
 */
function bindUpdateAriaExpandedOnInput( checkbox, button ) {
	var listener = updateAriaExpanded.bind( undefined, checkbox, button );
	// Whenever the checkbox state changes, update the `aria-expanded` state.
	checkbox.addEventListener( 'input', listener );

	return function () {
		checkbox.removeEventListener( 'input', listener );
	};
}

/**
 * Manually change the checkbox state when the button is focused and SPACE is pressed.
 *
 * @param {HTMLElement} button
 * @return {function(): void} Cleanup function that removes the added event listeners.
 * @ignore
 */
function bindToggleOnSpaceEnter( button ) {
	function isEnterOrSpace( /** @type {KeyboardEvent} */ event ) {
		return event.key === ' ' || event.key === 'Enter';
	}

	function onKeydown( /** @type {KeyboardEvent} */ event ) {
		// Only handle SPACE and ENTER.
		if ( !isEnterOrSpace( event ) ) {
			return;
		}
		// Prevent the browser from scrolling when pressing space. The browser will
		// try to do this unless the "button" element is a button or a checkbox.
		// Depending on the actual "button" element, this also possibly prevents a
		// native click event from being triggered so we programatically trigger a
		// click event in the keyup handler.
		event.preventDefault();
	}

	function onKeyup( /** @type {KeyboardEvent} */ event ) {
		// Only handle SPACE and ENTER.
		if ( !isEnterOrSpace( event ) ) {
			return;
		}

		// A native button element triggers a click event when the space or enter
		// keys are pressed. Since the passed in "button" may or may not be a
		// button, programmatically trigger a click event to make it act like a
		// button.
		button.click();
	}

	button.addEventListener( 'keydown', onKeydown );
	button.addEventListener( 'keyup', onKeyup );

	return function () {
		button.removeEventListener( 'keydown', onKeydown );
		button.removeEventListener( 'keyup', onKeyup );
	};
}

/**
 * Improve the interactivity of the sidebar panel by binding checkbox hack enhancements.
 *
 * @param {HTMLElement|null} checkbox
 * @param {HTMLElement|null} button
 * @param {HTMLElement|null} target
 * @return {void}
 */
function initMainMenu( checkbox, button, target ) {
	if ( checkbox instanceof HTMLInputElement && button && target ) {
		checkboxHack.bindToggleOnClick( checkbox, button );
		bindUpdateAriaExpandedOnInput( checkbox, button );
		updateAriaExpanded( checkbox, button );
		bindToggleOnSpaceEnter( button );
	}
}

/**
 * Improve the interactivity of the collapsed TOC by binding checkbox hack enhancements.
 *
 * @param {HTMLElement|null} checkbox
 * @param {HTMLElement|null} button
 * @param {HTMLElement|null} target
 * @return {void}
 */
function initCollapsedToc( checkbox, button, target ) {
	if ( checkbox instanceof HTMLInputElement && button && target ) {
		checkboxHack.bindToggleOnClick( checkbox, button );
		checkboxHack.bindDismissOnClickOutside( window, checkbox, button, target );
		checkboxHack.bindDismissOnClickLink( checkbox, target );
		bindUpdateAriaExpandedOnInput( checkbox, button );
		updateAriaExpanded( checkbox, button );
		bindToggleOnSpaceEnter( button );
	}
}

/**
 * Initialize main menu and collapsed TOC enhancements.
 *
 * @param {Document} document
 */
function init( document ) {
	initMainMenu(
		document.getElementById( 'mw-sidebar-checkbox' ),
		document.getElementById( 'mw-sidebar-button' ),
		document.getElementById( 'mw-navigation' )
	);

	initCollapsedToc(
		document.getElementById( 'vector-toc-collapsed-checkbox' ),
		document.getElementById( 'vector-toc-collapsed-button' ),
		document.getElementById( 'mw-panel-toc' )
	);
}

module.exports = {
	init: init
};
