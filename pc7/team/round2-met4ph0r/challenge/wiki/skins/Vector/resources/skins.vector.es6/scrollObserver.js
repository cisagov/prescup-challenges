const
	SCROLL_TITLE_HOOK = 'vector.page_title_scroll',
	SCROLL_TITLE_CONTEXT_ABOVE = 'scrolled-above-page-title',
	SCROLL_TITLE_CONTEXT_BELOW = 'scrolled-below-page-title',
	SCROLL_TITLE_ACTION = 'scroll-to-top',
	SCROLL_TOC_HOOK = 'vector.table_of_contents_scroll',
	SCROLL_TOC_CONTEXT_ABOVE = 'scrolled-above-table-of-contents',
	SCROLL_TOC_CONTEXT_BELOW = 'scrolled-below-table-of-contents',
	SCROLL_TOC_ACTION = 'scroll-to-toc',
	SCROLL_TOC_PARAMETER = 'table_of_contents';

/**
 * @typedef {Object} scrollVariables
 * @property {string} scrollHook
 * @property {string} scrollContextBelow
 * @property {string} scrollContextAbove
 * @property {string} scrollAction
 */

/**
 * Return the correct variables based on hook type.
 *
 * @param {string} hook the type of hook
 * @return {scrollVariables}
 */
function getScrollVariables( hook ) {
	const scrollVariables = {};
	if ( hook === 'page_title' ) {
		scrollVariables.scrollHook = SCROLL_TITLE_HOOK;
		scrollVariables.scrollContextBelow = SCROLL_TITLE_CONTEXT_BELOW;
		scrollVariables.scrollContextAbove = SCROLL_TITLE_CONTEXT_ABOVE;
		scrollVariables.scrollAction = SCROLL_TITLE_ACTION;
	} else if ( hook === SCROLL_TOC_PARAMETER ) {
		scrollVariables.scrollHook = SCROLL_TOC_HOOK;
		scrollVariables.scrollContextBelow = SCROLL_TOC_CONTEXT_BELOW;
		scrollVariables.scrollContextAbove = SCROLL_TOC_CONTEXT_ABOVE;
		scrollVariables.scrollAction = SCROLL_TOC_ACTION;
	}
	return scrollVariables;
}

/**
 * Fire a hook to be captured by WikimediaEvents for scroll event logging.
 *
 * @param {string} direction the scroll direction
 * @param {string} hook the hook to fire
 */
function fireScrollHook( direction, hook ) {
	const scrollVariables = getScrollVariables( hook );
	if ( Object.keys( scrollVariables ).length === 0 && scrollVariables.constructor === Object ) {
		return;
	}
	if ( direction === 'down' ) {
		mw.hook( scrollVariables.scrollHook ).fire( {
			context: scrollVariables.scrollContextBelow
		} );
	} else {
		mw.hook( scrollVariables.scrollHook ).fire( {
			context: scrollVariables.scrollContextAbove,
			action: scrollVariables.scrollAction
		} );
	}
}

/**
 * Create an observer for showing/hiding feature and for firing scroll event hooks.
 *
 * @param {Function} show functionality for when feature is visible
 * @param {Function} hide functionality for when feature is hidden
 * @return {IntersectionObserver}
 */
function initScrollObserver( show, hide ) {
	/* eslint-disable-next-line compat/compat */
	return new IntersectionObserver( function ( entries ) {
		if ( !entries[ 0 ].isIntersecting && entries[ 0 ].boundingClientRect.top < 0 ) {
			// Viewport has crossed the bottom edge of the target element.
			show();
		} else {
			// Viewport is above the bottom edge of the target element.
			hide();
		}
	} );
}

module.exports = {
	initScrollObserver,
	fireScrollHook
};
