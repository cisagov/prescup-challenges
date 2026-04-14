/** @module TableOfContents */

const SECTION_CLASS = 'sidebar-toc-list-item';
const ACTIVE_SECTION_CLASS = 'sidebar-toc-list-item-active';
const EXPANDED_SECTION_CLASS = 'sidebar-toc-list-item-expanded';
const PARENT_SECTION_CLASS = 'sidebar-toc-level-1';
const LINK_CLASS = 'sidebar-toc-link';
const TOGGLE_CLASS = 'sidebar-toc-toggle';
const TOC_COLLAPSED_CLASS = 'vector-toc-collapsed';
const TOC_NOT_COLLAPSED_CLASS = 'vector-toc-not-collapsed';
const TOC_ID = 'mw-panel-toc';
/**
 * TableOfContents Mustache templates
 */
const templateBody = require( /** @type {string} */ ( './templates/TableOfContents.mustache' ) );
const templateTocLine = require( /** @type {string} */ ( './templates/TableOfContents__line.mustache' ) );
/**
 * TableOfContents Config object for filling mustache templates
 */
const tableOfContentsConfig = require( /** @type {string} */ ( './tableOfContentsConfig.json' ) );

/**
 * @callback onHeadingClick
 * @param {string} id The id of the clicked list item.
 */

/**
 * @callback onToggleClick
 * @param {string} id The id of the list item corresponding to the arrow.
 */

/**
 * @callback onToggleCollapse
 */

/**
 * @typedef {Object} TableOfContentsProps
 * @property {HTMLElement} container The container element for the table of contents.
 * @property {onHeadingClick} onHeadingClick Called when an arrow is clicked.
 * @property {onToggleClick} onToggleClick Called when a list item is clicked.
 * @property {onToggleCollapse} onToggleCollapse Called when collapse toggle buttons are clicked.
 */

/**
 * @typedef {Object} Section
 * @property {number} toclevel
 * @property {string} anchor
 * @property {string} line
 * @property {string} number
 * @property {string} index
 * @property {number} byteoffset
 * @property {string} fromtitle
 * @property {boolean} is-parent-section
 * @property {boolean} is-top-level-section
 * @property {Section[]} array-sections
 * @property {string} level
 */

/**
 * @typedef {Object} SectionsListData
 * @property {boolean} is-vector-toc-beginning-enabled
 * @property {Section[]} array-sections
 * @property {boolean} vector-is-collapse-sections-enabled
 * @property {string} msg-vector-toc-heading
 * @property {number} number-section-count
 * @property {string} msg-vector-toc-beginning
 * @property {string} msg-vector-toc-toggle-position-title
 * @property {string} msg-vector-toc-toggle-position-sidebar
 */

/**
 * @typedef {Object} ArraySectionsData
 * @property {number} number-section-count
 * @property {Section[]} array-sections
 */

/**
 * Initializes the sidebar's Table of Contents.
 *
 * @param {TableOfContentsProps} props
 * @return {TableOfContents}
 */
module.exports = function tableOfContents( props ) {
	let /** @type {HTMLElement | undefined} */ activeTopSection;
	let /** @type {HTMLElement | undefined} */ activeSubSection;
	let /** @type {Array<HTMLElement>} */ expandedSections;

	/**
	 * @typedef {Object} activeSectionIds
	 * @property {string|undefined} parent - The active  top level section ID
	 * @property {string|undefined} child - The active subsection ID
	 */

	/**
	 * Get the ids of the active sections.
	 *
	 * @return {activeSectionIds}
	 */
	function getActiveSectionIds() {
		return {
			parent: ( activeTopSection ) ? activeTopSection.id : undefined,
			child: ( activeSubSection ) ? activeSubSection.id : undefined
		};
	}

	/**
	 * Does the user prefer reduced motion?
	 *
	 * @return {boolean}
	 */
	const prefersReducedMotion = () => {
		return window.matchMedia( '(prefers-reduced-motion: reduce)' ).matches;
	};

	/**
	 * Sets an `ACTIVE_SECTION_CLASS` on the element with an id that matches `id`.
	 * If the element is not a top level heading (e.g. element with the
	 * `PARENT_SECTION_CLASS`), the top level heading will also have the
	 * `ACTIVE_SECTION_CLASS`;
	 *
	 * @param {string} id The id of the element to be activated in the Table of Contents.
	 */
	function activateSection( id ) {
		const selectedTocSection = document.getElementById( id );
		const {
			parent: previousActiveTopId,
			child: previousActiveSubSectionId
		} = getActiveSectionIds();

		if (
			!selectedTocSection ||
			( previousActiveTopId === id ) ||
			( previousActiveSubSectionId === id )
		) {
			return;
		}

		const topSection = /** @type {HTMLElement} */ ( selectedTocSection.closest( `.${PARENT_SECTION_CLASS}` ) );

		if ( selectedTocSection === topSection ) {
			activeTopSection = topSection;
			activeTopSection.classList.add( ACTIVE_SECTION_CLASS );
		} else {
			activeTopSection = topSection;
			activeSubSection = selectedTocSection;
			activeTopSection.classList.add( ACTIVE_SECTION_CLASS );
			activeSubSection.classList.add( ACTIVE_SECTION_CLASS );
		}
	}

	/**
	 * Removes the `ACTIVE_SECTION_CLASS` from all ToC sections.
	 *
	 */
	function deactivateSections() {
		if ( activeSubSection ) {
			activeSubSection.classList.remove( ACTIVE_SECTION_CLASS );
			activeSubSection = undefined;
		}
		if ( activeTopSection ) {
			activeTopSection.classList.remove( ACTIVE_SECTION_CLASS );
			activeTopSection = undefined;
		}
	}

	/**
	 * Scroll active section into view if necessary
	 *
	 * @param {string} id The id of the element to be scrolled to in the Table of Contents.
	 */
	function scrollToActiveSection( id ) {
		const section = document.getElementById( id );
		if ( !section ) {
			return;
		}

		// Get currently visible active link
		let link = section.firstElementChild;
		// @ts-ignore
		if ( link && !link.offsetParent ) {
			// If active link is a hidden subsection, use active parent link
			const { parent: activeTopId } = getActiveSectionIds();
			const parentSection = document.getElementById( activeTopId || '' );
			if ( parentSection ) {
				link = parentSection.firstElementChild;
			} else {
				link = null;
			}
		}

		const isContainerScrollable = props.container.scrollHeight > props.container.clientHeight;
		if ( link && isContainerScrollable ) {
			const containerRect = props.container.getBoundingClientRect();
			const linkRect = link.getBoundingClientRect();

			// Pixels above or below the TOC where we start scrolling the active section into view
			const hiddenThreshold = 100;
			const midpoint = ( containerRect.bottom - containerRect.top ) / 2;
			const linkHiddenTopValue = containerRect.top - linkRect.top;
			// Because the bottom of the TOC can extend below the viewport,
			// min() is used to find the value where the active section first becomes hidden
			const linkHiddenBottomValue = linkRect.bottom -
				Math.min( containerRect.bottom, window.innerHeight );

			// Respect 'prefers-reduced-motion' user preference
			const scrollBehavior = prefersReducedMotion() ? 'smooth' : undefined;

			// Manually increment and decrement TOC scroll rather than using scrollToView
			// in order to account for threshold
			if ( linkHiddenTopValue + hiddenThreshold > 0 ) {
				props.container.scrollTo( {
					top: props.container.scrollTop - linkHiddenTopValue - midpoint,
					behavior: scrollBehavior
				} );
			}
			if ( linkHiddenBottomValue + hiddenThreshold > 0 ) {
				props.container.scrollTo( {
					top: props.container.scrollTop + linkHiddenBottomValue + midpoint,
					behavior: scrollBehavior
				} );
			}
		}
	}

	/**
	 * Adds the `EXPANDED_SECTION_CLASS` CSS class name
	 * to a top level heading in the ToC.
	 *
	 * @param {string} id
	 */
	function expandSection( id ) {
		const tocSection = document.getElementById( id );

		if ( !tocSection ) {
			return;
		}

		const parentSection = /** @type {HTMLElement} */ ( tocSection.closest( `.${PARENT_SECTION_CLASS}` ) );
		const toggle = tocSection.querySelector( `.${TOGGLE_CLASS}` );

		if ( parentSection && toggle && expandedSections.indexOf( parentSection ) < 0 ) {
			toggle.setAttribute( 'aria-expanded', 'true' );
			parentSection.classList.add( EXPANDED_SECTION_CLASS );
			expandedSections.push( parentSection );
		}
	}

	/**
	 * Get the IDs of expanded sections.
	 *
	 * @return {Array<string>}
	 */
	function getExpandedSectionIds() {
		return expandedSections.map( ( s ) => s.id );
	}

	/**
	 *
	 * @param {string} id
	 */
	function changeActiveSection( id ) {

		const { parent: activeParentId, child: activeChildId } = getActiveSectionIds();

		if ( id === activeParentId && id === activeChildId ) {
			return;
		} else {
			deactivateSections();
			activateSection( id );
			scrollToActiveSection( id );
		}
	}

	/**
	 * @param {string} id
	 * @return {boolean}
	 */
	function isTopLevelSection( id ) {
		const section = document.getElementById( id );
		return !!section && section.classList.contains( PARENT_SECTION_CLASS );
	}

	/**
	 * Removes all `EXPANDED_SECTION_CLASS` CSS class names
	 * from the top level sections in the ToC.
	 *
	 * @param {Array<string>} [selectedIds]
	 */
	function collapseSections( selectedIds ) {
		const sectionIdsToCollapse = selectedIds || getExpandedSectionIds();
		expandedSections = expandedSections.filter( function ( section ) {
			const isSelected = sectionIdsToCollapse.indexOf( section.id ) > -1;
			const toggle = isSelected ? section.getElementsByClassName( TOGGLE_CLASS ) : undefined;
			if ( isSelected && toggle && toggle.length > 0 ) {
				toggle[ 0 ].setAttribute( 'aria-expanded', 'false' );
				section.classList.remove( EXPANDED_SECTION_CLASS );
				return false;
			}
			return true;
		} );
	}

	/**
	 * @param {string} id
	 */
	function toggleExpandSection( id ) {
		const expandedSectionIds = getExpandedSectionIds();
		const indexOfExpandedSectionId = expandedSectionIds.indexOf( id );
		if ( isTopLevelSection( id ) ) {
			if ( indexOfExpandedSectionId >= 0 ) {
				collapseSections( [ id ] );
			} else {
				expandSection( id );
			}
		}
	}

	/**
	 * Set aria-expanded attribute for all toggle buttons.
	 */
	function initializeExpandedStatus() {
		const parentSections = props.container.querySelectorAll( `.${PARENT_SECTION_CLASS}` );
		parentSections.forEach( ( section ) => {
			const expanded = section.classList.contains( EXPANDED_SECTION_CLASS );
			const toggle = section.querySelector( `.${TOGGLE_CLASS}` );
			if ( toggle ) {
				toggle.setAttribute( 'aria-expanded', expanded.toString() );
			}
		} );
	}

	/**
	 * Bind event listener for clicking on show/hide Table of Contents links.
	 */
	function bindCollapseToggleListeners() {
		// Initialize toc collapsed status
		document.body.classList.add( TOC_NOT_COLLAPSED_CLASS );

		const showHideTocElement = document.querySelectorAll( '#sidebar-toc-label button' );
		showHideTocElement.forEach( function ( btn ) {
			btn.addEventListener( 'click', () => {
				document.body.classList.toggle( TOC_COLLAPSED_CLASS );
				document.body.classList.toggle( TOC_NOT_COLLAPSED_CLASS );

				props.onToggleCollapse();
			} );
		} );
	}

	/**
	 * Bind event listeners for clicking on section headings and toggle buttons.
	 */
	function bindSubsectionToggleListeners() {
		props.container.addEventListener( 'click', function ( e ) {
			if (
				!( e.target instanceof HTMLElement )
			) {
				return;
			}

			const tocSection =
				/** @type {HTMLElement | null} */ ( e.target.closest( `.${SECTION_CLASS}` ) );

			if ( tocSection && tocSection.id ) {
				// In case section link contains HTML,
				// test if click occurs on any child elements.
				if ( e.target.closest( `.${LINK_CLASS}` ) ) {
					props.onHeadingClick( tocSection.id );
				}
				// Toggle button does not contain child elements,
				// so classList check will suffice.
				if ( e.target.classList.contains( TOGGLE_CLASS ) ) {
					props.onToggleClick( tocSection.id );
				}
			}

		} );
	}

	/**
	 * Binds event listeners and sets the default state of the component.
	 */
	function initialize() {
		// Sync component state to the default rendered state of the table of contents.
		expandedSections = Array.from(
			props.container.querySelectorAll( `.${EXPANDED_SECTION_CLASS}` )
		);

		// Initialize toggle buttons aria-expanded attribute.
		initializeExpandedStatus();

		// Bind event listeners.
		bindSubsectionToggleListeners();
		bindCollapseToggleListeners();

		mw.hook( 'wikipage.tableOfContents' ).add( reloadTableOfContents );
	}

	/**
	 * Reexpands all sections that were expanded before the table of contents was reloaded.
	 * Edited Sections are not reexpanded, as the ID of the edited section is changed after reload.
	 */
	function reExpandSections() {
		initializeExpandedStatus();
		const expandedSectionIds = getExpandedSectionIds();
		for ( const id of expandedSectionIds ) {
			expandSection( id );
		}
	}

	/**
	 * Reloads the table of contents from saved data
	 *
	 * @param {Section[]} sections
	 */
	function reloadTableOfContents( sections ) {
		if ( sections.length < 1 ) {
			reloadPartialHTML( TOC_ID, '' );
			return;
		}
		mw.loader.using( 'mediawiki.template.mustache' ).then( () => {
			reloadPartialHTML( TOC_ID, getTableOfContentsHTML( sections ) );
			// Reexpand sections that were expanded before the table of contents was reloaded.
			reExpandSections();
			// Initialize Collapse toggle buttons
			bindCollapseToggleListeners();
		} );
	}

	/**
	 * Replaces the contents of the given element with the given HTML
	 *
	 * @param {string} elementId
	 * @param {string} html
	 * @param {boolean} setInnerHTML
	 */
	function reloadPartialHTML( elementId, html, setInnerHTML = true ) {
		const htmlElement = document.getElementById( elementId );
		if ( htmlElement ) {
			if ( setInnerHTML ) {
				htmlElement.innerHTML = html;
			} else if ( htmlElement.outerHTML ) {
				htmlElement.outerHTML = html;
			} else { // IF outerHTML property access is not supported
				const tmpContainer = document.createElement( 'div' );
				tmpContainer.innerHTML = html.trim();
				const childNode = tmpContainer.firstChild;
				if ( childNode ) {
					const tmpElement = document.createElement( 'div' );
					tmpElement.setAttribute( 'id', `div-tmp-${elementId}` );
					const parentNode = htmlElement.parentNode;
					if ( parentNode ) {
						parentNode.replaceChild( tmpElement, htmlElement );
						parentNode.replaceChild( childNode, tmpElement );
					}
				}
			}
		}
	}

	/**
	 * Generates the HTML for the table of contents.
	 *
	 * @param {Section[]} sections
	 * @return {string}
	 */
	function getTableOfContentsHTML( sections ) {
		return getTableOfContentsListHtml( getTableOfContentsData( sections ) );
	}

	/**
	 * Generates the table of contents List HTML from the templates
	 *
	 * @param {Object} data
	 * @return {string}
	 */
	function getTableOfContentsListHtml( data ) {
		// @ts-ignore
		const mustacheCompiler = mw.template.getCompiler( 'mustache' );
		const compiledTemplateBody = mustacheCompiler.compile( templateBody );
		const compiledTemplateTocLine = mustacheCompiler.compile( templateTocLine );

		// Identifier 'TableOfContents__line' is not in camel case
		// (template name is 'TableOfContents__line')
		const partials = {
			TableOfContents__line: compiledTemplateTocLine // eslint-disable-line camelcase
		};

		return compiledTemplateBody.render( data, partials ).html();
	}

	/**
	 * @param {Section[]} sections
	 * @return {SectionsListData}
	 */
	function getTableOfContentsData( sections ) {
		return {
			'number-section-count': sections.length,
			'msg-vector-toc-heading': mw.message( 'vector-toc-heading' ).text(),
			'msg-vector-toc-toggle-position-sidebar': mw.message( 'vector-toc-toggle-position-sidebar' ).text(),
			'msg-vector-toc-toggle-position-title': mw.message( 'vector-toc-toggle-position-title' ).text(),
			'msg-vector-toc-beginning': mw.message( 'vector-toc-beginning' ).text(),
			'array-sections': getTableOfContentsSectionsData( sections, 1 ),
			'vector-is-collapse-sections-enabled': sections.length >= tableOfContentsConfig.VectorTableOfContentsCollapseAtCount,
			'is-vector-toc-beginning-enabled': tableOfContentsConfig.VectorTableOfContentsBeginning
		};
	}

	/**
	 * Prepares the data for rendering the table of contents,
	 * nesting child sections within their parent sections.
	 * This shoul yield the same result as the php function SkinVector22::getTocData(),
	 * please make sure to keep them in sync.
	 *
	 * @param {Section[]} sections
	 * @param {number} toclevel
	 * @return {Section[]}
	 */
	function getTableOfContentsSectionsData( sections, toclevel = 1 ) {
		const data = [];
		for ( let i = 0; i < sections.length; i++ ) {
			const section = sections[ i ];
			if ( section.toclevel === toclevel ) {
				const childSections = getTableOfContentsSectionsData(
					sections.slice( i + 1 ),
					toclevel + 1
				);
				section[ 'array-sections' ] = childSections;
				section[ 'is-top-level-section' ] = toclevel === 1;
				section[ 'is-parent-section' ] = Object.keys( childSections ).length > 0;
				data.push( section );
			}
			// Child section belongs to a higher parent.
			if ( section.toclevel < toclevel ) {
				return data;
			}
		}

		return data;
	}

	initialize();

	/**
	 * @typedef {Object} TableOfContents
	 * @property {changeActiveSection} changeActiveSection
	 * @property {expandSection} expandSection
	 * @property {toggleExpandSection} toggleExpandSection
	 * @property {string} ACTIVE_SECTION_CLASS
	 * @property {string} EXPANDED_SECTION_CLASS
	 * @property {string} LINK_CLASS
	 * @property {string} TOGGLE_CLASS
	 */
	return {
		expandSection,
		changeActiveSection,
		toggleExpandSection,
		ACTIVE_SECTION_CLASS,
		EXPANDED_SECTION_CLASS,
		LINK_CLASS,
		TOGGLE_CLASS
	};
};
