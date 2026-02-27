import { htmlUserLanguageAttributes } from './utils';
import { placeholder } from './utils';

import { articleToolbarTemplate, ARTICLE_TOOLBAR_TEMPLATE_DATA_LEGACY } from './ArticleToolbar.stories.data';
import { userLinksTemplateLegacy } from './UserLinks.stories.data';
import { menuTemplate, legacyMenuTemplate } from './Menu.stories.data';
import { PERSONAL_MENU_TEMPLATE_DATA } from './UserLinks.stories.data';
import { vectorMenuTemplate, moreData, variantsData } from './MenuDropdown.stories.data';
import { searchBoxData, searchBoxTemplate, SEARCH_TEMPLATE_PARTIALS } from './SearchBox.stories.data';
import { SIDEBAR_DATA, SIDEBAR_TEMPLATE_PARTIALS, OPT_OUT_DATA,
	sidebarLegacyTemplate, sidebarTemplate } from './Sidebar.stories.data';
import { FOOTER_TEMPLATE_DATA, FOOTER_TEMPLATE_PARTIALS,
	footerTemplate } from './Footer.stories.data';
import { logoTemplate } from './Logo.stories.data';

export const NAVIGATION_TEMPLATE_DATA = {
	loggedInWithVariantsAndOptOut: Object.assign( {}, {
		'data-portlets': Object.assign( {}, ARTICLE_TOOLBAR_TEMPLATE_DATA_LEGACY[ 'data-portlets' ], {
			'data-personal': PERSONAL_MENU_TEMPLATE_DATA.loggedInWithEcho,
			'data-variants': variantsData
		} ),
		'data-search-box': searchBoxData,
		'data-portlets-sidebar': SIDEBAR_DATA.withPortals,
		'msg-navigation-heading': 'Navigation menu',
		'html-logo-attributes': `class="mw-wiki-logo" href="/wiki/Main_Page" title="Visit the main page"`
	}, OPT_OUT_DATA ),
	loggedOutWithVariants: {
		'data-portlets': Object.assign( {}, ARTICLE_TOOLBAR_TEMPLATE_DATA_LEGACY[ 'data-portlets' ], {
			'data-personal': PERSONAL_MENU_TEMPLATE_DATA.loggedOut,
			'data-variants': variantsData
		} ),
		'data-search-box': searchBoxData,
		'data-portlets-sidebar': SIDEBAR_DATA.withPortals,
		'msg-navigation-heading': 'Navigation menu',
		'html-logo-attributes': `class="mw-wiki-logo" href="/wiki/Main_Page" title="Visit the main page"`
	},
	loggedInWithMoreActions: {
		'data-portlets': Object.assign( {}, ARTICLE_TOOLBAR_TEMPLATE_DATA_LEGACY[ 'data-portlets' ], {
			'data-personal': PERSONAL_MENU_TEMPLATE_DATA.loggedInWithEcho,
			'data-actions': moreData
		} ),
		'data-search-box': searchBoxData,
		'data-portlets-sidebar': SIDEBAR_DATA.withPortals,
		'msg-navigation-heading': 'Navigation menu',
		'html-logo-attributes': `class="mw-wiki-logo" href="/wiki/Main_Page" title="Visit the main page"`
	}
};

export const TEMPLATE_PARTIALS = Object.assign( {}, SIDEBAR_TEMPLATE_PARTIALS, {
	Logo: logoTemplate,
	ArticleToolbar: articleToolbarTemplate,
	SearchBox: searchBoxTemplate,
	LegacySidebar: sidebarLegacyTemplate,
	Sidebar: sidebarTemplate,
	LegacyMenu: legacyMenuTemplate,
	VectorMenu: vectorMenuTemplate,
	Menu: menuTemplate,
	LegacyUserLinks: userLinksTemplateLegacy,
	Footer: footerTemplate
}, FOOTER_TEMPLATE_PARTIALS, SEARCH_TEMPLATE_PARTIALS );

/**
 * @type {Indicator[]}
 */
const DATA_INDICATORS = [ {
	id: 'mw-indicator-good-star',
	class: 'mw-indicator',
	html: `<a href="/wiki/Wikipedia:Good_articles"
		title="This is a good article. Follow the link for more information.">
			<img alt="This is a good article. Follow the link for more information."
				src="//upload.wikimedia.org/wikipedia/en/thumb/9/94/Symbol_support_vote.svg/19px-Symbol_support_vote.svg.png" decoding="async" width="19" height="20"
				srcset="//upload.wikimedia.org/wikipedia/en/thumb/9/94/Symbol_support_vote.svg/29px-Symbol_support_vote.svg.png 1.5x, //upload.wikimedia.org/wikipedia/en/thumb/9/94/Symbol_support_vote.svg/39px-Symbol_support_vote.svg.png 2x" data-file-width="180" data-file-height="185" />
	</a>`
},
{
	id: 'mw-indicator-pp-autoreview',
	class: 'mw-indicator',
	html: `<a href="/wiki/Wikipedia:Protection_policy#pending"
		title="All edits by unregistered and new users are subject to review prior to becoming visible to unregistered users">
		<img alt="Page protected with pending changes" src="//upload.wikimedia.org/wikipedia/en/thumb/b/b7/Pending-protection-shackle.svg/20px-Pending-protection-shackle.svg.png"
			decoding="async" width="20" height="20" srcset="//upload.wikimedia.org/wikipedia/en/thumb/b/b7/Pending-protection-shackle.svg/30px-Pending-protection-shackle.svg.png 1.5x, //upload.wikimedia.org/wikipedia/en/thumb/b/b7/Pending-protection-shackle.svg/40px-Pending-protection-shackle.svg.png 2x" data-file-width="512" data-file-height="512" />
	</a>`
} ];

export const LEGACY_TEMPLATE_DATA = {
	'html-title': 'Vector 2019',
	'html-title-heading': '<h1 id="firstHeading" class="firstHeading">Vector 2019</h1>',
	'is-article': true,
	'msg-tagline': 'From Wikipedia, the free encyclopedia',
	'html-user-language-attributes': htmlUserLanguageAttributes,
	'msg-vector-jumptonavigation': 'Jump to navigation',
	'msg-vector-jumptosearch': 'Jump to search',

	// site specific
	'data-footer': FOOTER_TEMPLATE_DATA,
	'html-site-notice': placeholder( 'a site notice or central notice banner may go here', 70 ),

	// article dependent
	'html-body-content': `${placeholder( 'Article content goes here' )}
		<div class="printfooter">
			Retrieved from ‘<a dir="ltr" href="#">https://en.wikipedia.org/w/index.php?title=this&oldid=blah</a>’
		</div>`,
	'html-categories': placeholder( 'Category links component from mediawiki core', 50 ),

	// extension dependent..
	'html-after-content': placeholder( 'Extensions can add here e.g. Related Articles.', 100 ),
	'array-indicators': DATA_INDICATORS,
	'html-subtitle': placeholder( 'Extensions can configure subtitle', 20 )
};

export const MODERN_TEMPLATE_DATA = {
	'html-title': 'Vector 2020',
	'page-isarticle': true,
	'msg-tagline': 'From Wikipedia, the free encyclopedia',
	'html-user-language-attributes': htmlUserLanguageAttributes,
	'msg-vector-jumptonavigation': 'Jump to navigation',
	'msg-vector-jumptosearch': 'Jump to search',

	// site specific
	'data-footer': FOOTER_TEMPLATE_DATA,
	'html-site-notice': placeholder( 'a site notice or central notice banner may go here', 70 ),

	// article dependent
	'array-indicators': DATA_INDICATORS,
	'html-body-content': `${placeholder( 'Article content goes here' )}
		<div class="printfooter">
		Retrieved from ‘<a dir="ltr" href="#">https://en.wikipedia.org/w/index.php?title=this&oldid=blah</a>’
		</div>`,
	'html-categories': placeholder( 'Category links component from mediawiki core', 50 )
};
