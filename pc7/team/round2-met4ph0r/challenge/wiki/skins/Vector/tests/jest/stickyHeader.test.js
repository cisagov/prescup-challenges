const mustache = require( 'mustache' );
const fs = require( 'fs' );
const tocContainerTemplate = fs.readFileSync( 'includes/templates/TableOfContentsContainer.mustache', 'utf8' );
const stickyHeaderTemplate = fs.readFileSync( 'includes/templates/StickyHeader.mustache', 'utf8' );
const buttonTemplate = fs.readFileSync( 'includes/templates/Button.mustache', 'utf8' );
const menuTemplate = fs.readFileSync( 'includes/templates/Menu.mustache', 'utf8' );
const sticky = require( '../../resources/skins.vector.es6/stickyHeader.js' );
const { userLinksHTML } = require( './userLinksData.js' );

const defaultButtonsTemplateData = [ {
	href: '#',
	id: 'ca-talk-sticky-header',
	event: 'talk-sticky-header',
	icon: 'wikimedia-speechBubbles',
	'is-quiet': true,
	'tab-index': '-1',
	class: 'sticky-header-icon'
}, {
	href: '#',
	id: 'ca-history-sticky-header',
	event: 'history-sticky-header',
	icon: 'wikimedia-history',
	'is-quiet': true,
	'tab-index': '-1',
	class: 'sticky-header-icon'
}, {
	href: '#',
	id: 'ca-watchstar-sticky-header',
	event: 'watch-sticky-header',
	icon: 'wikimedia-star',
	'is-quiet': true,
	'tab-index': '-1',
	class: 'sticky-header-icon mw-watchlink'
} ];

const editButtonsTemplateData = [ {
	href: '#',
	id: 'ca-ve-edit-sticky-header',
	event: 've-edit-sticky-header',
	icon: 'wikimedia-edit',
	'is-quiet': true,
	'tab-index': '-1',
	class: 'sticky-header-icon'
}, {
	href: '#',
	id: 'ca-edit-sticky-header',
	event: 'wikitext-edit-sticky-header',
	icon: 'wikimedia-wikiText',
	'is-quiet': true,
	'tab-index': '-1',
	class: 'sticky-header-icon'
}, {
	href: '#',
	id: 'ca-viewsource-sticky-header',
	event: 'wikimedia-editLock',
	icon: 'wikimedia-star',
	'is-quiet': true,
	'tab-index': '-1',
	class: 'sticky-header-icon'
} ];

const templateData = {
	'data-sticky-header-toc': {
		id: 'p-sticky-header-toc',
		class: 'mw-portlet mw-portlet-sticky-header-toc vector-sticky-header-toc',
		'html-items': '',
		'html-vector-menu-checkbox-attributes': 'tabindex="-1"',
		'html-vector-menu-heading-attributes': 'tabindex="-1"',
		'heading-class': 'mw-ui-button mw-ui-quiet mw-ui-icon mw-ui-icon-element mw-ui-icon-wikimedia-listBullet'
	},
	'data-primary-action': {
		id: 'p-lang-btn-sticky-header',
		class: 'mw-interlanguage-selector',
		'is-quiet': true,
		tabindex: '-1',
		label: '0 languages',
		'html-vector-button-icon': '<span class="mw-ui-icon mw-ui-icon-wikimedia-language"></span>',
		event: 'ui.dropdown-p-lang-btn-sticky-header'
	},
	'data-button-start': {
		label: 'search',
		icon: 'wikimedia-search',
		'is-quiet': true,
		tabindex: '-1',
		class: 'vector-sticky-header-search-toggle',
		event: 'ui.vector-sticky-search-form.icon'
	},
	'data-search': {},
	'data-buttons': defaultButtonsTemplateData.concat( editButtonsTemplateData )
};

const renderedHTML = mustache.render( stickyHeaderTemplate, templateData, {
	Button: buttonTemplate,
	Menu: menuTemplate,
	SearchBox: '<div> </div>' // ignore SearchBox for this test
} );

beforeEach( () => {
	document.body.innerHTML = renderedHTML;
} );

test( 'Sticky header renders', () => {
	expect( document.body.innerHTML ).toMatchSnapshot();
} );

describe( 'sticky header', () => {
	test( 'prepareUserMenu removes gadgets from dropdown', async () => {
		const menu = document.createElement( 'div' );
		menu.innerHTML = userLinksHTML;
		const userMenu = /** @type {Element} */ ( menu.querySelector( '#' + sticky.USER_MENU_ID ) );
		const newMenu = sticky.prepareUserMenu( userMenu );
		// check classes have been updated and removed.
		expect( userMenu.querySelectorAll( '.user-links-collapsible-item' ).length > 0 ).toBeTruthy();
		expect( userMenu.querySelectorAll( '.mw-list-item-js' ).length > 0 ).toBeTruthy();
		expect( newMenu.querySelectorAll( '.user-links-collapsible-item' ).length ).toBe( 0 );
		expect( newMenu.querySelectorAll( '.mw-list-item-js' ).length ).toBe( 0 );
	} );

	describe( 'moveToc', () => {
		const sidebarTocContainerClass = 'vector-sticky-toc-container';
		const stickyTocContainerClass = 'vector-menu-content';
		const tocId = 'mw-panel-toc';

		function setupToc() {
			const sidebarTocContainerHTML = mustache.render( tocContainerTemplate, {
				'data-toc': [ '' ]
			}, {
				TableOfContents: '<div id="mw-panel-toc" class="sidebar-toc"></div>'
			} );
			var sidebarTocContainerTemplate = document.createElement( 'template' );
			sidebarTocContainerTemplate.innerHTML = sidebarTocContainerHTML;
			document.body.appendChild( sidebarTocContainerTemplate.content );
		}

		test( 'moves toc to stickyheader and sidebar', () => {
			setupToc();
			const toc = /** @type {Element} */ ( document.getElementById( tocId ) );
			expect( /** @type {Element} */
				( toc.parentNode ).classList.contains( sidebarTocContainerClass ) ).toBeTruthy();
			sticky.moveToc( 'stickyheader' );
			expect( /** @type {Element} */
				( toc.parentNode ).classList.contains( stickyTocContainerClass ) ).toBeTruthy();
			sticky.moveToc( 'sidebar' );
			expect( /** @type {Element} */
				( toc.parentNode ).classList.contains( sidebarTocContainerClass ) ).toBeTruthy();
		} );
	} );
} );
