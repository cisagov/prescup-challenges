import mustache from 'mustache';
import { PERSONAL_MENU_TEMPLATE_DATA, USER_LINKS_LOGGED_IN_TEMPLATE_DATA, USER_LINKS_LOGGED_OUT_TEMPLATE_DATA } from './UserLinks.stories.data';
import { userLinksTemplateLegacy, userLinksTemplate,
	USER_LINK_PARTIALS } from './UserLinks.stories.data';
import '../resources/skins.vector.styles.legacy/components/UserLinks.less';
import '../resources/skins.vector.styles/components/UserLinks.less';

export default {
	title: 'UserLinks'
};

export const legacyLoggedOut = () => mustache.render(
	userLinksTemplateLegacy,
	{
		'data-personal': PERSONAL_MENU_TEMPLATE_DATA.loggedOut
	},
	USER_LINK_PARTIALS
);

export const legacyLoggedInWithEcho = () => mustache.render(
	userLinksTemplateLegacy,
	{
		'data-personal': PERSONAL_MENU_TEMPLATE_DATA.loggedInWithEcho
	},
	USER_LINK_PARTIALS
);

export const legacyLoggedInWithULS = () => mustache.render(
	userLinksTemplateLegacy,
	{
		'data-personal': PERSONAL_MENU_TEMPLATE_DATA.loggedInWithULS
	},
	USER_LINK_PARTIALS
);

export const loggedInUserLinks = () => mustache.render(
	userLinksTemplate,
	USER_LINKS_LOGGED_IN_TEMPLATE_DATA,
	USER_LINK_PARTIALS
);

export const loggedOutUserLinks = () => mustache.render(
	userLinksTemplate,
	USER_LINKS_LOGGED_OUT_TEMPLATE_DATA,
	USER_LINK_PARTIALS
);
