import msgs from '../i18n/en.json';
import mustache from 'mustache';
import { menuTemplate, legacyMenuTemplate } from './Menu.stories.data';
import userLinksTemplateLegacy from '!!raw-loader!../includes/templates/LegacyUserLinks.mustache';
import userLinksTemplate from '!!raw-loader!../includes/templates/UserLinks.mustache';
import userLinksLogoutTemplate from '!!raw-loader!../includes/templates/UserLinks__logout.mustache';
import userLinksLoginTemplate from '!!raw-loader!../includes/templates/UserLinks__login.mustache';
import { helperClassName, helperMakeMenuData } from './utils';

/**
 * Legacy User Links
 */

const ECHO_ITEMS = `<li id="pt-notifications-alert"><a href="/wiki/Special:Notifications" class="mw-echo-notifications-badge mw-echo-notification-badge-nojs oo-ui-icon-bell mw-echo-notifications-badge-all-read" data-counter-num="0" data-counter-text="0" title="Your alerts">Alerts (0)</a></li><li id="pt-notifications-notice"><a href="/wiki/Special:Notifications" class="mw-echo-notifications-badge mw-echo-notification-badge-nojs oo-ui-icon-tray" data-counter-num="3" data-counter-text="3" title="Your notices">Notices (3)</a></li>`;
const USERNAME_ITEM = `<li id="pt-userpage"><a href="/wiki/User:WikiUser" dir="auto" title="Your user page [⌃⌥.]" accesskey=".">WikiUser</a></li>`;
const REST_ITEMS = `<li id="pt-mytalk"><a href="/wiki/User_talk:WikiUser" title="Your talk page [⌃⌥n]" accesskey="n">Talk</a></li><li id="pt-sandbox"><a href="/wiki/User:WikiUser/sandbox" title="Your sandbox">Sandbox</a></li><li id="pt-preferences"><a href="/wiki/Special:Preferences" title="Your preferences">Preferences</a></li><li id="pt-betafeatures"><a href="/wiki/Special:Preferences#mw-prefsection-betafeatures" title="Beta features">Beta</a></li><li id="pt-watchlist"><a href="/wiki/Special:Watchlist" title="A list of pages you are monitoring for changes [⌃⌥l]" accesskey="l">Watchlist</a></li><li id="pt-mycontris"><a href="/wiki/Special:Contributions/WikiUser" title="A list of your contributions [⌃⌥y]" accesskey="y">Contributions</a></li>`;
const LOGOUT_ITEM = `<li id="pt-logout"><a href="/w/index.php?title=Special:UserLogout&amp;returnto=Main+Page&amp;returntoquery=useskin%3Dvector" title="Log out">Log out</a></li>`;
const ULS_LANGUAGE_SELECTOR = '<li class="uls-trigger active"><a href="#">English</a></li>';

/**
 * @type {MenuDefinition}
 */
const loggedOut = helperMakeMenuData(
	'personal',
	`<li id="pt-anonuserpage">Not logged in</li><li id="pt-anontalk"><a href="/wiki/Special:MyTalk" title="Discussion about edits from this IP address [⌃⌥n]" accesskey="n">Talk</a></li><li id="pt-anoncontribs"><a href="/wiki/Special:MyContributions" title="A list of edits made from this IP address [⌃⌥y]" accesskey="y">Contributions</a></li><li id="pt-createaccount"><a href="/w/index.php?title=Special:CreateAccount&amp;returnto=Main+Page" title="You are encouraged to create an account and log in; however, it is not mandatory">Create account</a></li><li id="pt-login"><a href="/w/index.php?title=Special:UserLogin&amp;returnto=Main+Page" title="You're encouraged to log in; however, it's not mandatory. [⌃⌥o]" accesskey="o">Log in</a></li>`,
	helperClassName( 'vector-user-menu-legacy' )
);

/**
 * @type {MenuDefinition}
 */
const loggedInWithEcho = helperMakeMenuData(
	'personal',
	`${USERNAME_ITEM}${ECHO_ITEMS}${REST_ITEMS}${LOGOUT_ITEM}`,
	helperClassName( 'vector-user-menu-legacy' )
);

/**
 * @type {MenuDefinition}
 */
const loggedInWithULS = helperMakeMenuData(
	'personal',
	`${ULS_LANGUAGE_SELECTOR}${USERNAME_ITEM}${ECHO_ITEMS}${REST_ITEMS}${LOGOUT_ITEM}`,
	helperClassName( 'vector-user-menu-legacy' )
);

/**
 * @type {Object.<string, MenuDefinition>}
 */
const PERSONAL_MENU_TEMPLATE_DATA = {
	loggedOut,
	loggedInWithEcho,
	loggedInWithULS
};

/**
 * Modern User Links
 */

const LOGGED_IN_ITEMS = `
	<li id="pt-userpage" class="user-links-collapsible-item mw-list-item"><a class="mw-ui-icon mw-ui-icon-before mw-ui-icon-userAvatar mw-ui-icon-wikimedia-userAvatar" href="/wiki/User:Admin" title="Your user page [⌃⌥.]" accesskey="."><span>Admin</span></a></li>
	<li id="pt-mytalk" class="mw-list-item"><a class="mw-ui-icon mw-ui-icon-before mw-ui-icon-userTalk mw-ui-icon-wikimedia-userTalk" href="/wiki/User_talk:Admin" title="Your talk page [⌃⌥n]" accesskey="n"><span>Talk</span></a></li>
	<li id="pt-sandbox" class="new mw-list-item"><a class="mw-ui-icon mw-ui-icon-before mw-ui-icon-sandbox mw-ui-icon-wikimedia-sandbox" href="/w/index.php?title=User:Admin/sandbox&amp;action=edit&amp;redlink=1" title="Your sandbox (page does not exist)"><span>Sandbox</span></a></li>
	<li id="pt-preferences" class="mw-list-item"><a class="mw-ui-icon mw-ui-icon-before mw-ui-icon-settings mw-ui-icon-wikimedia-settings" href="/wiki/Special:Preferences" title="Your preferences"><span>Preferences</span></a></li>
	<li id="pt-betafeatures" class="mw-list-item"><a class="mw-ui-icon mw-ui-icon-before mw-ui-icon-labFlask mw-ui-icon-wikimedia-labFlask" href="/wiki/Special:Preferences#mw-prefsection-betafeatures" title="Beta features"><span>Beta</span></a></li>
	<li id="pt-watchlist" class="user-links-collapsible-item mw-list-item"><a class="mw-ui-icon mw-ui-icon-before mw-ui-icon-watchlist mw-ui-icon-wikimedia-watchlist" href="/wiki/Special:Watchlist" title="A list of pages you are monitoring for changes [⌃⌥l]" accesskey="l"><span>Watchlist</span></a></li>
	<li id="pt-uploads" class="mw-list-item"><a class="mw-ui-icon mw-ui-icon-before mw-ui-icon-imageGallery mw-ui-icon-wikimedia-imageGallery" href="/w/index.php?title=Special:ListFiles/Admin&amp;ilshowall=1" title="List of files you have uploaded"><span>Uploads</span></a></li>
	<li id="pt-mycontris" class="mw-list-item"><a class="mw-ui-icon mw-ui-icon-before mw-ui-icon-userContributions mw-ui-icon-wikimedia-userContributions" href="/wiki/Special:Contributions/Admin" title="A list of your contributions [⌃⌥y]" accesskey="y"><span>Contributions</span></a></li>
`;

const LOGGED_OUT_ITEMS = `
	<li id="pt-anontalk" class="mw-list-item"><a href="/wiki/Special:MyTalk" title="Discussion about edits from this IP address [⌃⌥n]" accesskey="n"><span>Talk</span></a></li>
	<li id="pt-anoncontribs" class="mw-list-item"><a href="/wiki/Special:MyContributions" title="A list of edits made from this IP address [⌃⌥y]" accesskey="y"><span>Contributions</span></a></li>
`;

const LOGGED_IN_OVERFLOW_ITEMS = `
	<li id="pt-userpage-2" class="user-links-collapsible-item mw-list-item"><a href="/wiki/User:Admin" class="mw-ui-button mw-ui-quiet" title="Your user page [⌃⌥.]" accesskey="."><span>Admin</span></a></li>
	<li id="pt-notifications-alert" class="mw-list-item"><a href="/wiki/Special:Notifications" class="mw-echo-notifications-badge mw-echo-notification-badge-nojs oo-ui-icon-bell mw-echo-notifications-badge-all-read" data-counter-num="0" data-counter-text="0" title="Your alerts"><span>Alerts (0)</span></a></li>
	<li id="pt-notifications-notice" class="mw-list-item"><a href="/wiki/Special:Notifications" class="mw-echo-notifications-badge mw-echo-notification-badge-nojs oo-ui-icon-tray mw-echo-notifications-badge-all-read" data-counter-num="0" data-counter-text="0" title="Your notices"><span>Notices (0)</span></a></li>
	<li id="pt-watchlist-2" class="user-links-collapsible-item mw-list-item"><a href="/wiki/Special:Watchlist" class="mw-ui-button mw-ui-quiet mw-ui-icon mw-ui-icon-element mw-ui-icon-watchlist mw-ui-icon-wikimedia-watchlist" title="A list of pages you are monitoring for changes [⌃⌥l]" accesskey="l"><span>Watchlist</span></a></li>
`;

const LOGGED_OUT_OVERFLOW_ITEMS = `
	<li id="pt-createaccount-2" class="user-links-collapsible-item mw-list-item"><a href="/w/index.php?title=Special:CreateAccount&amp;returnto=Main+Page" class="mw-ui-button mw-ui-quiet" title="You are encouraged to create an account and log in; however, it is not mandatory"><span>Create account</span></a></li>
`;

const loggedInData = {
	class: 'vector-user-menu vector-menu-dropdown vector-user-menu-logged-in',
	'heading-class': 'mw-ui-button mw-ui-quiet mw-ui-icon mw-ui-icon-element mw-ui-icon-wikimedia-userAvatar',
	'html-after-portal': mustache.render( userLinksLogoutTemplate, {
		htmlLogout: `<a class="vector-menu-content-item vector-menu-content-item-logout mw-ui-icon mw-ui-icon-before mw-ui-icon-wikimedia-logOut" data-mw="interface" href="/w/index.php?title=Special:UserLogout&amp;returnto=Main+Page"><span>Log out</span></a>`
	} ),
	'is-anon': false,
	'is-dropdown': true,
	'has-label': true
};

const loggedOutData = {
	class: 'vector-user-menu vector-menu-dropdown vector-user-menu-logged-out',
	'heading-class': 'mw-ui-button mw-ui-quiet mw-ui-icon mw-ui-icon-element mw-ui-icon-wikimedia-ellipsis',
	'html-before-portal': mustache.render( userLinksLoginTemplate, {
		htmlCreateAccount: `<a href="/w/index.php?title=Special:CreateAccount&amp;returnto=Special%3AUserLogout" icon="userAvatar" class="user-links-collapsible-item vector-menu-content-item mw-ui-icon mw-ui-icon-before mw-ui-icon-wikimedia-userAvatar" title="You are encouraged to create an account and log in; however, it is not mandatory"><span>Create account</span></a>`,
		htmlLogin: `<a class="vector-menu-content-item vector-menu-content-item-login mw-ui-icon mw-ui-icon-before mw-ui-icon-wikimedia-logIn" href="/w/index.php?title=Special:UserLogin&amp;returnto=Main+Page" title="You are encouraged to log in; however, it is not mandatory [ctrl-option-o]" accesskey="o"><span>Log in</span></a>`,
		msgLearnMore: msgs[ 'vector-anon-user-menu-pages' ],
		htmlLearnMoreLink: `<a href="/wiki/Help:Introduction"><span>${msgs[ 'vector-anon-user-menu-pages-learn' ]}</span></a>:`
	} ),
	'is-anon': false,
	'is-dropdown': true,
	'has-label': true
};

const overflowData = {
	class: 'vector-menu vector-user-menu-overflow',
	'heading-class': '',
	'is-dropdown': false
};

/**
 * @type {UserLinksDefinition}
 */
const USER_LINKS_LOGGED_IN_TEMPLATE_DATA = {
	'data-user-menu-overflow': helperMakeMenuData( 'vector-user-menu-overflow', LOGGED_IN_OVERFLOW_ITEMS, overflowData ),
	'data-user-menu': helperMakeMenuData( 'personal-more', LOGGED_IN_ITEMS, loggedInData )
};

/**
 * @type {UserLinksDefinition}
 */
const USER_LINKS_LOGGED_OUT_TEMPLATE_DATA = {
	'data-user-menu-overflow': helperMakeMenuData( 'vector-user-menu-overflow', LOGGED_OUT_OVERFLOW_ITEMS, overflowData ),
	'data-user-menu': helperMakeMenuData( 'personal-more', LOGGED_OUT_ITEMS, loggedOutData )
};

const USER_LINK_PARTIALS = {
	Menu: menuTemplate,
	LegacyMenu: legacyMenuTemplate
};

export {
	PERSONAL_MENU_TEMPLATE_DATA,
	USER_LINKS_LOGGED_IN_TEMPLATE_DATA,
	USER_LINKS_LOGGED_OUT_TEMPLATE_DATA,
	USER_LINK_PARTIALS,
	userLinksTemplateLegacy,
	userLinksTemplate
};
