/**
 * Functions and variables to implement sticky header.
 */
const
	initSearchToggle = require( './searchToggle.js' ),
	STICKY_HEADER_ID = 'vector-sticky-header',
	STICKY_HEADER_APPENDED_ID = '-sticky-header',
	STICKY_HEADER_APPENDED_PARAM = [ 'wvprov', 'sticky-header' ],
	STICKY_HEADER_VISIBLE_CLASS = 'vector-sticky-header-visible',
	STICKY_HEADER_USER_MENU_CONTAINER_CLASS = 'vector-sticky-header-icon-end',
	TOC_ID = 'mw-panel-toc',
	FIRST_HEADING_ID = 'firstHeading',
	USER_MENU_ID = 'p-personal',
	ULS_STICKY_CLASS = 'uls-dialog-sticky',
	ULS_HIDE_CLASS = 'uls-dialog-sticky-hide',
	VECTOR_USER_LINKS_SELECTOR = '.vector-user-links',
	SEARCH_TOGGLE_SELECTOR = '.vector-sticky-header-search-toggle',
	STICKY_HEADER_EDIT_EXPERIMENT_NAME = 'vector.sticky_header_edit',
	STICKY_HEADER_EXPERIMENT_NAME = 'vector.sticky_header';

/**
 * Copies attribute from an element to another.
 *
 * @param {Element} from
 * @param {Element} to
 * @param {string} attribute
 */
function copyAttribute( from, to, attribute ) {
	const fromAttr = from.getAttribute( attribute );
	if ( fromAttr ) {
		to.setAttribute( attribute, fromAttr );
	}
}

/**
 * Show the sticky header.
 */
function show() {
	document.body.classList.add( STICKY_HEADER_VISIBLE_CLASS );
	document.body.classList.remove( ULS_HIDE_CLASS );
}

/**
 * Hide the sticky header.
 */
function hide() {
	document.body.classList.remove( STICKY_HEADER_VISIBLE_CLASS );
	document.body.classList.add( ULS_HIDE_CLASS );
}

/**
 * Moves the TOC element to a new parent container.
 *
 * @param {string} position The position to move the TOC into: sidebar or stickyheader
 */
function moveToc( position ) {
	const toc = document.getElementById( TOC_ID );
	const currTocContainer = toc && toc.parentElement;
	if ( !toc || !currTocContainer ) {
		return;
	}

	// FIXME: Remove after Ia263c606dce5a6060b6b29fbaedc49cef3e17a5c has been in prod for 5 days
	const isCachedHtml = document.querySelector( '.mw-table-of-contents-container.mw-sticky-header-element' );

	let newTocContainer;
	const sidebarTocContainerClass = isCachedHtml ? 'mw-table-of-contents-container' : 'vector-sticky-toc-container';
	const stickyHeaderTocContainerClass = 'vector-menu-content';
	// Avoid moving TOC if unnecessary
	if ( !currTocContainer.classList.contains( sidebarTocContainerClass ) && position === 'sidebar' ) {
		newTocContainer = document.querySelector( `.${sidebarTocContainerClass}` );
	} else if ( !currTocContainer.classList.contains( stickyHeaderTocContainerClass ) && position === 'stickyheader' ) {
		newTocContainer = document.querySelector( `.vector-sticky-header-toc .${stickyHeaderTocContainerClass}` );
	}

	if ( newTocContainer ) {
		newTocContainer.insertAdjacentElement( 'beforeend', toc );
	}
}

/**
 * Copies attribute from an element to another.
 *
 * @param {Element} from
 * @param {Element} to
 */
function copyButtonAttributes( from, to ) {
	copyAttribute( from, to, 'href' );
	copyAttribute( from, to, 'title' );
}

/**
 * Suffixes an attribute with a value that indicates it
 * relates to the sticky header to support click tracking instrumentation.
 *
 * @param {Element} node
 * @param {string} attribute
 */
function suffixStickyAttribute( node, attribute ) {
	const value = node.getAttribute( attribute );
	if ( value ) {
		node.setAttribute( attribute, value + STICKY_HEADER_APPENDED_ID );
	}
}

/**
 * Suffixes the href attribute of a node with a value that indicates it
 * relates to the sticky header to support tracking instrumentation.
 *
 * Distinct from suffixStickyAttribute as it's intended to support followed
 * links recording their origin.
 *
 * @param {Element} node
 */
function suffixStickyHref( node ) {
	/* eslint-disable compat/compat */
	// @ts-ignore
	const url = new URL( node.href );
	if ( url && !url.searchParams.has( STICKY_HEADER_APPENDED_PARAM[ 0 ] ) ) {
		url.searchParams.append(
			STICKY_HEADER_APPENDED_PARAM[ 0 ], STICKY_HEADER_APPENDED_PARAM[ 1 ]
		);
		// @ts-ignore
		node.href = url.toString();
	}
	/* eslint-enable compat/compat */
}

/**
 * Undoes the effect of suffixStickyHref
 *
 * @param {Element} node
 */
function unsuffixStickyHref( node ) {
	/* eslint-disable compat/compat */
	// @ts-ignore
	const url = new URL( node.href );
	url.searchParams.delete( STICKY_HEADER_APPENDED_PARAM[ 0 ] );
	// @ts-ignore
	node.href = url.toString();
	/* eslint-enable compat/compat */
}

/**
 * Makes a node trackable by our click tracking instrumentation.
 *
 * @param {Element} node
 */
function makeNodeTrackable( node ) {
	suffixStickyAttribute( node, 'id' );
	suffixStickyAttribute( node, 'data-event-name' );
}

/**
 * @param {Element} node
 */
function removeNode( node ) {
	if ( node.parentNode ) {
		node.parentNode.removeChild( node );
	}
}

/**
 * @param {NodeList} nodes
 * @param {string} className
 */
function removeClassFromNodes( nodes, className ) {
	Array.prototype.forEach.call( nodes, function ( node ) {
		node.classList.remove( className );
	} );
}

/**
 * @param {NodeList} nodes
 */
function removeNodes( nodes ) {
	Array.prototype.forEach.call( nodes, function ( node ) {
		node.parentNode.removeChild( node );
	} );
}

/**
 * Ensures a sticky header button has the correct attributes
 *
 * @param {Element} watchSticky
 * @param {string} status 'watched', 'unwatched', or 'temporary'
 */
function updateStickyWatchlink( watchSticky, status ) {
	watchSticky.classList.toggle( 'mw-ui-icon-wikimedia-star', status === 'unwatched' );
	watchSticky.classList.toggle( 'mw-ui-icon-wikimedia-unStar', status === 'watched' );
	watchSticky.classList.toggle( 'mw-ui-icon-wikimedia-halfStar', status === 'temporary' );
	watchSticky.setAttribute( 'data-event-name', status === 'unwatched' ? 'watch-sticky-header' : 'unwatch-sticky-header' );
}

/**
 * Callback for watchsar
 *
 * @param {jQuery} $link Watchstar link
 * @param {boolean} isWatched The page is watched
 * @param {string} [expiry] Optional expiry time
 */
function watchstarCallback( $link, isWatched, expiry ) {
	updateStickyWatchlink(
		// @ts-ignore
		$link[ 0 ],
		expiry !== 'infinity' ? 'temporary' :
			isWatched ? 'watched' : 'unwatched'
	);
}

/**
 * Makes sticky header icons functional for modern Vector.
 *
 * @param {Element} header
 * @param {Element|null} history
 * @param {Element|null} talk
 * @param {Element|null} subject
 * @param {Element|null} watch
 */
function prepareIcons( header, history, talk, subject, watch ) {
	const historySticky = header.querySelector( '#ca-history-sticky-header' ),
		talkSticky = header.querySelector( '#ca-talk-sticky-header' ),
		subjectSticky = header.querySelector( '#ca-subject-sticky-header' ),
		watchSticky = header.querySelector( '#ca-watchstar-sticky-header' );

	if ( !historySticky || !talkSticky || !subjectSticky || !watchSticky ) {
		throw new Error( 'Sticky header has unexpected HTML' );
	}

	if ( history ) {
		copyButtonAttributes( history, historySticky );
	} else {
		removeNode( historySticky );
	}

	if ( talk ) {
		copyButtonAttributes( talk, talkSticky );
	} else {
		removeNode( talkSticky );
	}

	if ( subject ) {
		copyButtonAttributes( subject, subjectSticky );
	} else {
		removeNode( subjectSticky );
	}

	if ( watch && watch.parentNode instanceof Element ) {
		const watchContainer = watch.parentNode;
		copyButtonAttributes( watch, watchSticky );
		updateStickyWatchlink(
			watchSticky,
			watchContainer.classList.contains( 'mw-watchlink-temp' ) ? 'temporary' :
				watchContainer.getAttribute( 'id' ) === 'ca-watch' ? 'unwatched' : 'watched'
		);

		const watchLib = require( /** @type {string} */( 'mediawiki.page.watch.ajax' ) );
		watchLib.watchstar( $( watchSticky ), mw.config.get( 'wgRelevantPageName' ), watchstarCallback );
	} else {
		removeNode( watchSticky );
	}
}

/**
 * Render sticky header edit or protected page icons for modern Vector.
 *
 * @param {Element} header
 * @param {Element|null} primaryEdit
 * @param {boolean} isProtected
 * @param {Element|null} secondaryEdit
 * @param {Element|null} addSection
 * @param {Function} disableStickyHeader function to call to disable the sticky
 *  header.
 */
function prepareEditIcons(
	header,
	primaryEdit,
	isProtected,
	secondaryEdit,
	addSection,
	disableStickyHeader
) {
	const
		primaryEditSticky = header.querySelector(
			'#ca-ve-edit-sticky-header'
		),
		protectedSticky = header.querySelector(
			'#ca-viewsource-sticky-header'
		),
		wikitextSticky = header.querySelector(
			'#ca-edit-sticky-header'
		),
		addSectionSticky = header.querySelector(
			'#ca-addsection-sticky-header'
		);

	if ( addSectionSticky ) {
		if ( addSection ) {
			copyButtonAttributes( addSection, addSectionSticky );
			suffixStickyHref( addSectionSticky );
		} else {
			removeNode( addSectionSticky );
		}
	}

	// If no primary edit icon is present the feature is disabled.
	if ( !primaryEditSticky || !wikitextSticky || !protectedSticky ) {
		return;
	}

	if ( !primaryEdit ) {
		removeNode( protectedSticky );
		removeNode( wikitextSticky );
		removeNode( primaryEditSticky );
		return;
	} else if ( isProtected ) {
		removeNode( wikitextSticky );
		removeNode( primaryEditSticky );
		copyButtonAttributes( primaryEdit, protectedSticky );
		suffixStickyHref( protectedSticky );
	} else {
		removeNode( protectedSticky );
		copyButtonAttributes( primaryEdit, primaryEditSticky );
		suffixStickyHref( primaryEditSticky );

		primaryEditSticky.addEventListener( 'click', function ( ev ) {
			const target = ev.target;
			const $ve = $( primaryEdit );
			if ( target && $ve.length ) {
				const event = $.Event( 'click' );
				suffixStickyHref( $ve[ 0 ] );
				$ve.trigger( event );
				unsuffixStickyHref( $ve[ 0 ] );
				// The link has been progressively enhanced.
				if ( event.isDefaultPrevented() ) {
					disableStickyHeader();
					ev.preventDefault();
				}
			}
		} );
		if ( secondaryEdit ) {
			copyButtonAttributes( secondaryEdit, wikitextSticky );
			suffixStickyHref( wikitextSticky );
			wikitextSticky.addEventListener( 'click', function ( ev ) {
				const target = ev.target;
				if ( target ) {
					const $edit = $( secondaryEdit );
					if ( $edit.length ) {
						const event = $.Event( 'click' );
						suffixStickyHref( $edit[ 0 ] );
						$edit.trigger( event );
						unsuffixStickyHref( $edit[ 0 ] );
						// The link has been progressively enhanced.
						if ( event.isDefaultPrevented() ) {
							disableStickyHeader();
							ev.preventDefault();
						}
					}
				}
			} );
		} else {
			removeNode( wikitextSticky );
		}
	}
}

/**
 * Check if element is in viewport.
 *
 * @param {Element} element
 * @return {boolean}
 */
function isInViewport( element ) {
	const rect = element.getBoundingClientRect();
	return (
		rect.top >= 0 &&
		rect.left >= 0 &&
		rect.bottom <= ( window.innerHeight || document.documentElement.clientHeight ) &&
		rect.right <= ( window.innerWidth || document.documentElement.clientWidth )
	);
}

/**
 * Add hooks for sticky header when Visual Editor is used.
 *
 * @param {Element} stickyIntersection intersection element
 * @param {IntersectionObserver} observer
 */
function addVisualEditorHooks( stickyIntersection, observer ) {
	// When Visual Editor is activated, hide the sticky header.
	mw.hook( 've.activationStart' ).add( () => {
		hide();
		observer.unobserve( stickyIntersection );
	} );

	// When Visual Editor is deactivated (by clicking "Read" tab at top of page), show sticky header
	// by re-triggering the observer.
	mw.hook( 've.deactivationComplete' ).add( () => {
		// Wait for the next repaint or we might calculate that
		// sticky header should not be visible (T299114)
		requestAnimationFrame( () => {
			observer.observe( stickyIntersection );
		} );
	} );

	// After saving edits, re-apply the sticky header if the target is not in the viewport.
	mw.hook( 'postEdit.afterRemoval' ).add( () => {
		if ( !isInViewport( stickyIntersection ) ) {
			show();
			observer.observe( stickyIntersection );
		}
	} );
}

/**
 * @param {Element} userMenu
 * @return {Element} cloned userMenu
 */
function prepareUserMenu( userMenu ) {
	const
		// Type declaration needed because of https://github.com/Microsoft/TypeScript/issues/3734#issuecomment-118934518
		userMenuClone = /** @type {Element} */( userMenu.cloneNode( true ) ),
		userMenuStickyElementsWithIds = userMenuClone.querySelectorAll( '[ id ], [ data-event-name ]' );
	// Update all ids of the cloned user menu to make them unique.
	makeNodeTrackable( userMenuClone );
	userMenuStickyElementsWithIds.forEach( makeNodeTrackable );
	// Remove portlet links added by gadgets using mw.util.addPortletLink, T291426
	removeNodes( userMenuClone.querySelectorAll( '.mw-list-item-js' ) );
	removeClassFromNodes(
		userMenuClone.querySelectorAll( '.user-links-collapsible-item' ),
		'user-links-collapsible-item'
	);
	// Prevents user menu from being focusable, T290201
	const userMenuCheckbox = userMenuClone.querySelector( 'input' );
	if ( userMenuCheckbox ) {
		userMenuCheckbox.setAttribute( 'tabindex', '-1' );
	}
	return userMenuClone;
}

/**
 * Makes sticky header functional for modern Vector.
 *
 * @param {Element} header
 * @param {Element} userMenu
 * @param {Element} userMenuStickyContainer
 * @param {IntersectionObserver} stickyObserver
 * @param {Element} stickyIntersection
 * @param {boolean} disableEditIcons
 */
function makeStickyHeaderFunctional(
	header,
	userMenu,
	userMenuStickyContainer,
	stickyObserver,
	stickyIntersection,
	disableEditIcons
) {
	const
		userMenuStickyContainerInner = userMenuStickyContainer
			.querySelector( VECTOR_USER_LINKS_SELECTOR );

	// Clone the updated user menu to the sticky header.
	if ( userMenuStickyContainerInner ) {
		userMenuStickyContainerInner.appendChild( prepareUserMenu( userMenu ) );
	}

	let namespaceName = mw.config.get( 'wgCanonicalNamespace' );
	const namespaceNumber = mw.config.get( 'wgNamespaceNumber' );
	if ( namespaceNumber >= 0 && namespaceNumber % 2 === 1 ) {
		// Remove '_talk' to get subject namespace
		namespaceName = namespaceName.slice( 0, -5 );
	}
	// Title::getNamespaceKey()
	let namespaceKey = namespaceName.toLowerCase() || 'main';
	if ( namespaceKey === 'file' ) {
		namespaceKey = 'image';
	}
	const namespaceTabId = 'ca-nstab-' + namespaceKey;

	prepareIcons( header,
		document.querySelector( '#ca-history a' ),
		document.querySelector( '#ca-talk:not( .selected ) a' ),
		document.querySelector( '#' + namespaceTabId + ':not( .selected ) a' ),
		document.querySelector( '#ca-watch a, #ca-unwatch a' )
	);

	const veEdit = document.querySelector( '#ca-ve-edit a' );
	const ceEdit = document.querySelector( '#ca-edit a' );
	const protectedEdit = document.querySelector( '#ca-viewsource a' );
	const isProtected = !!protectedEdit;
	// For sticky header edit A/B test, conditionally remove the edit icon by setting null.
	// Otherwise, use either protected, ve, or source edit (in that order).
	const primaryEdit = disableEditIcons ? null : protectedEdit || veEdit || ceEdit;
	const secondaryEdit = veEdit ? ceEdit : null;
	const disableStickyHeader = () => {
		document.body.classList.remove( STICKY_HEADER_VISIBLE_CLASS );
		stickyObserver.unobserve( stickyIntersection );
	};
	const addSection = document.querySelector( '#ca-addsection a' );

	prepareEditIcons(
		header,
		primaryEdit,
		isProtected,
		secondaryEdit,
		addSection,
		disableStickyHeader
	);

	stickyObserver.observe( stickyIntersection );
}

/**
 * @param {Element} header
 */
function setupSearchIfNeeded( header ) {
	const
		searchToggle = header.querySelector( SEARCH_TOGGLE_SELECTOR );

	if ( !document.body.classList.contains( 'skin-vector-search-vue' ) ) {
		return;
	}

	if ( searchToggle ) {
		initSearchToggle( searchToggle );
	}
}

/**
 * Determines if sticky header should be visible for a given namespace.
 *
 * @param {number} namespaceNumber
 * @return {boolean}
 */
function isAllowedNamespace( namespaceNumber ) {
	// Corresponds to Main, Main talk, User, User talk, Wikipedia,
	// Template, Help, Category, Portal, Module.
	const allowedNamespaceNumbers = [ 0, 1, 2, 3, 4, 10, 12, 14, 100, 828 ];
	return allowedNamespaceNumbers.indexOf( namespaceNumber ) > -1;
}

/**
 * Determines if sticky header should be visible for a given action.
 *
 * @param {string} action
 * @return {boolean}
 */
function isAllowedAction( action ) {
	const disallowedActions = [ 'history', 'edit' ],
		hasDiffId = mw.config.get( 'wgDiffOldId' );
	return disallowedActions.indexOf( action ) < 0 && !hasDiffId;
}

/**
 * @typedef {Object} StickyHeaderProps
 * @property {Element} header
 * @property {Element} userMenu
 * @property {IntersectionObserver} observer
 * @property {Element} stickyIntersection
 * @property {boolean} disableEditIcons
 */

/**
 * @param {StickyHeaderProps} props
 */
function initStickyHeader( props ) {
	const userMenuStickyContainer = document.getElementsByClassName(
		STICKY_HEADER_USER_MENU_CONTAINER_CLASS
	)[ 0 ];

	makeStickyHeaderFunctional(
		props.header,
		props.userMenu,
		userMenuStickyContainer,
		props.observer,
		props.stickyIntersection,
		props.disableEditIcons
	);

	setupSearchIfNeeded( props.header );
	addVisualEditorHooks( props.stickyIntersection, props.observer );

	// Make sure ULS outside sticky header disables the sticky header behaviour.
	// @ts-ignore
	mw.hook( 'mw.uls.compact_language_links.open' ).add( function ( $trigger ) {
		if ( $trigger.attr( 'id' ) !== 'p-lang-btn-sticky-header' ) {
			const bodyClassList = document.body.classList;
			bodyClassList.remove( ULS_HIDE_CLASS );
			bodyClassList.remove( ULS_STICKY_CLASS );
		}
	} );

	// Make sure ULS dialog is sticky.
	const langBtn = props.header.querySelector( '#p-lang-btn-sticky-header' );
	if ( langBtn ) {
		langBtn.addEventListener( 'click', function () {
			const bodyClassList = document.body.classList;
			bodyClassList.remove( ULS_HIDE_CLASS );
			bodyClassList.add( ULS_STICKY_CLASS );
		} );
	}
}

module.exports = {
	show,
	hide,
	moveToc,
	prepareUserMenu,
	isAllowedNamespace,
	isAllowedAction,
	initStickyHeader,
	STICKY_HEADER_ID,
	FIRST_HEADING_ID,
	USER_MENU_ID,
	STICKY_HEADER_EDIT_EXPERIMENT_NAME,
	STICKY_HEADER_EXPERIMENT_NAME
};
