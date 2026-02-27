const { addPortletLinkHandler } = require( '../../resources/skins.vector.js/dropdownMenus.js' );

describe( 'addPortletLinkHandler', () => {

	test( 'Adds a span with icon class to dropdown menus', () => {

		// <li> element is the assumed HTML output of mw.util.addPortlet
		document.body.innerHTML = `
		<ul class="vector-menu vector-menu-dropdown">
			<li class="mw-list-item mw-list-item-js" id="test-id">
				<a href="#test-href">
					<span>
						test link content
					</span>
				</a>
			</li>
		</ul>`;

		const mockPortletItem = document.getElementById( 'test-id' );
		// @ts-ignore: mockPortletItem possibly 'null'.
		addPortletLinkHandler( mockPortletItem, { id: 'test-id' } );
		expect( document.body.innerHTML ).toMatchSnapshot();
	} );

	test( 'Does not add an icon when noicon class is present', () => {

		// <li> element is the assumed HTML output of mw.util.addPortlet
		document.body.innerHTML = `
		<ul class="vector-menu vector-menu-dropdown vector-menu-dropdown-noicon">
			<li class="mw-list-item mw-list-item-js" id="test-id">
				<a href="#test-href">
					<span>
						test link content
					</span>
				</a>
			</li>
		</ul>`;

		const mockPortletItem = document.getElementById( 'test-id' );
		// @ts-ignore: mockPortletItem possibly 'null'.
		addPortletLinkHandler( mockPortletItem, { id: 'test-id' } );
		expect( document.body.innerHTML ).toMatchSnapshot();
	} );

	test( 'JS portlet should be moved to more menu (#p-cactions) at narrow widths', () => {

		// <li> element is the assumed HTML output of mw.util.addPortlet
		document.body.innerHTML = `
		<div class="mw-article-toolbar-container" style="width:1000px">

			<div id="p-namespaces" style="width:1001px"></div>

			<div id="p-variants"></div>

			<div id="p-cactions">
				<ul>
				</ul>
			</div>

			<ul id="p-views" class="vector-menu vector-menu-dropdown">
				<li class="mw-list-item mw-list-item-js" id="test-id">
					<a href="#test-href">
						<span>
							test link content
						</span>
					</a>
				</li>
			</ul>
		</div>`;

		const mockPortletItem = document.getElementById( 'test-id' );
		// @ts-ignore: mockPortletItem  possibly 'null'.
		addPortletLinkHandler( mockPortletItem, { id: 'test-id' } );
		expect( document.body.innerHTML ).toMatchSnapshot();
	} );
} );
