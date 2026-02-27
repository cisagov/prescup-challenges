const mustache = require( 'mustache' );
const fs = require( 'fs' );
const tableOfContentsTemplate = fs.readFileSync( 'includes/templates/TableOfContents.mustache', 'utf8' );
const tableOfContentsLineTemplate = fs.readFileSync( 'includes/templates/TableOfContents__line.mustache', 'utf8' );
const initTableOfContents = require( '../../resources/skins.vector.es6/tableOfContents.js' );

let /** @type {HTMLElement} */ fooSection,
	/** @type {HTMLElement} */ barSection,
	/** @type {HTMLElement} */ bazSection,
	/** @type {HTMLElement} */ quxSection,
	/** @type {HTMLElement} */ quuxSection;
const onHeadingClick = jest.fn();
const onToggleClick = jest.fn();
const onToggleCollapse = jest.fn();

/**
 * @param {Object} templateProps
 * @return {string}
 */
function render( templateProps = {} ) {
	const templateData = Object.assign( {
		'is-vector-toc-beginning-enabled': true,
		'msg-vector-toc-beginning': 'Beginning',
		'msg-vector-toc-heading': 'Contents',
		'vector-is-collapse-sections-enabled': false,
		'array-sections': [ {
			toclevel: 1,
			number: '1',
			line: 'foo',
			anchor: 'foo',
			'is-top-level-section': true,
			'is-parent-section': false,
			'array-sections': null
		}, {
			toclevel: 1,
			number: '2',
			line: 'bar',
			anchor: 'bar',
			'is-top-level-section': true,
			'is-parent-section': true,
			'vector-button-label': 'Toggle bar subsection',
			'array-sections': [ {
				toclevel: 2,
				number: '2.1',
				line: 'baz',
				anchor: 'baz',
				'is-top-level-section': false,
				'is-parent-section': true,
				'array-sections': [ {
					toclevel: 3,
					number: '2.1.1',
					line: 'qux',
					anchor: 'qux',
					'is-top-level-section': false,
					'is-parent-section': false,
					'array-sections': null
				} ]
			} ]
		}, {
			toclevel: 1,
			number: '3',
			line: 'quux',
			anchor: 'quux',
			'is-top-level-section': true,
			'is-parent-section': false,
			'array-sections': null
		} ]
	}, templateProps );

	return mustache.render( tableOfContentsTemplate, templateData, {
		TableOfContents__line: tableOfContentsLineTemplate // eslint-disable-line camelcase
	} );
}

/**
 * @param {Object} templateProps
 * @return {module:TableOfContents~TableOfContents}
 */
function mount( templateProps = {} ) {
	document.body.innerHTML = render( templateProps );
	const toc = initTableOfContents( {
		container: /** @type {HTMLElement} */ ( document.getElementById( 'mw-panel-toc' ) ),
		onHeadingClick,
		onToggleClick,
		onToggleCollapse
	} );

	fooSection = /** @type {HTMLElement} */ ( document.getElementById( 'toc-foo' ) );
	barSection = /** @type {HTMLElement} */ ( document.getElementById( 'toc-bar' ) );
	bazSection = /** @type {HTMLElement} */ ( document.getElementById( 'toc-baz' ) );
	quxSection = /** @type {HTMLElement} */ ( document.getElementById( 'toc-qux' ) );
	quuxSection = /** @type {HTMLElement} */ ( document.getElementById( 'toc-quux' ) );
	return toc;
}

describe( 'Table of contents', () => {
	beforeEach( () => {
		// @ts-ignore
		global.window.matchMedia = jest.fn( () => ( {} ) );
	} );

	describe( 'renders', () => {
		test( 'when `vector-is-collapse-sections-enabled` is false', () => {
			const toc = mount();
			expect( document.body.innerHTML ).toMatchSnapshot();
			expect( barSection.classList.contains( toc.EXPANDED_SECTION_CLASS ) ).toEqual( true );
		} );
		test( 'when `vector-is-collapse-sections-enabled` is true', () => {
			const toc = mount( { 'vector-is-collapse-sections-enabled': true } );
			expect( document.body.innerHTML ).toMatchSnapshot();
			expect( barSection.classList.contains( toc.EXPANDED_SECTION_CLASS ) ).toEqual( false );
		} );
		test( 'toggles for top level parent sections', () => {
			const toc = mount();
			expect( fooSection.getElementsByClassName( toc.TOGGLE_CLASS ).length ).toEqual( 0 );
			expect( barSection.getElementsByClassName( toc.TOGGLE_CLASS ).length ).toEqual( 1 );
			expect( bazSection.getElementsByClassName( toc.TOGGLE_CLASS ).length ).toEqual( 0 );
			expect( quxSection.getElementsByClassName( toc.TOGGLE_CLASS ).length ).toEqual( 0 );
			expect( quuxSection.getElementsByClassName( toc.TOGGLE_CLASS ).length ).toEqual( 0 );
		} );
	} );

	describe( 'binds event listeners', () => {
		test( 'for onHeadingClick', () => {
			const toc = mount();
			const heading = /** @type {HTMLElement} */ ( document.querySelector( `#toc-foo .${toc.LINK_CLASS}` ) );
			heading.click();

			expect( onToggleClick ).not.toBeCalled();
			expect( onHeadingClick ).toBeCalled();
		} );
		test( 'for onToggleClick', () => {
			const toc = mount();
			const toggle = /** @type {HTMLElement} */ ( document.querySelector( `#toc-bar .${toc.TOGGLE_CLASS}` ) );
			toggle.click();

			expect( onHeadingClick ).not.toBeCalled();
			expect( onToggleClick ).toBeCalled();
		} );
	} );

	describe( 'applies correct classes', () => {
		test( 'when changing active sections', () => {
			const toc = mount( { 'vector-is-collapse-sections-enabled': true } );
			toc.changeActiveSection( 'toc-foo' );
			expect( fooSection.classList.contains( toc.ACTIVE_SECTION_CLASS ) ).toEqual( true );
			expect( barSection.classList.contains( toc.ACTIVE_SECTION_CLASS ) ).toEqual( false );
			expect( bazSection.classList.contains( toc.ACTIVE_SECTION_CLASS ) ).toEqual( false );
			expect( quxSection.classList.contains( toc.ACTIVE_SECTION_CLASS ) ).toEqual( false );
			expect( quuxSection.classList.contains( toc.ACTIVE_SECTION_CLASS ) ).toEqual( false );

			toc.changeActiveSection( 'toc-bar' );
			expect( fooSection.classList.contains( toc.ACTIVE_SECTION_CLASS ) ).toEqual( false );
			expect( barSection.classList.contains( toc.ACTIVE_SECTION_CLASS ) ).toEqual( true );
			expect( bazSection.classList.contains( toc.ACTIVE_SECTION_CLASS ) ).toEqual( false );
			expect( quxSection.classList.contains( toc.ACTIVE_SECTION_CLASS ) ).toEqual( false );
			expect( quuxSection.classList.contains( toc.ACTIVE_SECTION_CLASS ) ).toEqual( false );

			toc.changeActiveSection( 'toc-baz' );
			expect( fooSection.classList.contains( toc.ACTIVE_SECTION_CLASS ) ).toEqual( false );
			expect( barSection.classList.contains( toc.ACTIVE_SECTION_CLASS ) ).toEqual( true );
			expect( bazSection.classList.contains( toc.ACTIVE_SECTION_CLASS ) ).toEqual( true );
			expect( quxSection.classList.contains( toc.ACTIVE_SECTION_CLASS ) ).toEqual( false );
			expect( quuxSection.classList.contains( toc.ACTIVE_SECTION_CLASS ) ).toEqual( false );

			toc.changeActiveSection( 'toc-qux' );
			expect( fooSection.classList.contains( toc.ACTIVE_SECTION_CLASS ) ).toEqual( false );
			expect( barSection.classList.contains( toc.ACTIVE_SECTION_CLASS ) ).toEqual( true );
			expect( bazSection.classList.contains( toc.ACTIVE_SECTION_CLASS ) ).toEqual( false );
			expect( quxSection.classList.contains( toc.ACTIVE_SECTION_CLASS ) ).toEqual( true );
			expect( quuxSection.classList.contains( toc.ACTIVE_SECTION_CLASS ) ).toEqual( false );
		} );

		test( 'when expanding sections', () => {
			const toc = mount();
			toc.expandSection( 'toc-bar' );
			expect( barSection.classList.contains( toc.EXPANDED_SECTION_CLASS ) ).toEqual( true );
		} );

		test( 'when toggling sections', () => {
			const toc = mount();
			toc.toggleExpandSection( 'toc-bar' );
			expect( barSection.classList.contains( toc.EXPANDED_SECTION_CLASS ) ).toEqual( false );
			toc.toggleExpandSection( 'toc-bar' );
			expect( barSection.classList.contains( toc.EXPANDED_SECTION_CLASS ) ).toEqual( true );
		} );
	} );

	describe( 'applies the correct aria attributes', () => {
		test( 'when initialized', () => {
			const spy = jest.spyOn( mw, 'hook' );
			const toc = mount();
			const toggleButton = /** @type {HTMLElement} */ ( barSection.querySelector( `.${toc.TOGGLE_CLASS}` ) );

			expect( toggleButton.getAttribute( 'aria-expanded' ) ).toEqual( 'true' );
			expect( spy ).toBeCalledWith( 'wikipage.tableOfContents' );
		} );

		test( 'when expanding sections', () => {
			const toc = mount();
			const toggleButton = /** @type {HTMLElement} */ ( barSection.querySelector( `.${toc.TOGGLE_CLASS}` ) );

			toc.expandSection( 'toc-bar' );
			expect( toggleButton.getAttribute( 'aria-expanded' ) ).toEqual( 'true' );
		} );

		test( 'when toggling sections', () => {
			const toc = mount();
			const toggleButton = /** @type {HTMLElement} */ ( barSection.querySelector( `.${toc.TOGGLE_CLASS}` ) );

			toc.toggleExpandSection( 'toc-bar' );
			expect( toggleButton.getAttribute( 'aria-expanded' ) ).toEqual( 'false' );

			toc.toggleExpandSection( 'toc-bar' );
			expect( toggleButton.getAttribute( 'aria-expanded' ) ).toEqual( 'true' );
		} );
	} );
} );
