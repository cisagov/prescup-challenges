import headerTemplate from '!!raw-loader!../includes/templates/Header.mustache';
import { logoTemplate as Logo, LOGO_TEMPLATE_DATA } from './Logo.stories.data';
import { searchBoxTemplate as SearchBox,
	searchBoxDataWithCollapsing,
	SEARCH_TEMPLATE_PARTIALS } from './SearchBox.stories.data';
import { userLinksTemplate as UserLinks,
	USER_LINKS_LOGGED_OUT_TEMPLATE_DATA,
	USER_LINK_PARTIALS } from './UserLinks.stories.data';

export const HEADER_TEMPLATE_PARTIALS = Object.assign( {
	SearchBox,
	Logo,
	UserLinks
}, SEARCH_TEMPLATE_PARTIALS, USER_LINK_PARTIALS );

export { headerTemplate };

export const HEADER_TEMPLATE_DATA = Object.assign( {
	'msg-vector-main-menu-tooltip': 'Tooltip',
	'msg-vector-action-toggle-sidebar': 'Toggle',
	'data-search-box': searchBoxDataWithCollapsing,
	'data-vector-user-links': USER_LINKS_LOGGED_OUT_TEMPLATE_DATA
}, LOGO_TEMPLATE_DATA.wordmarkTaglineIcon );
