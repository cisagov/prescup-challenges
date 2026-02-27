import searchBoxTemplate from '!!raw-loader!../includes/templates/SearchBox.mustache';
import Button from '!!raw-loader!../includes/templates/Button.mustache';
import { htmlUserLanguageAttributes } from './utils';

const INPUT_ATTRIBUTES = 'type="search" name="search" placeholder="Search Wikipedia" title="Search Wikipedia [⌃⌥f]" accesskey="f" id="searchInput" autocomplete="off"';
const FULL_TEXT_ATTRIBUTES = 'name="fulltext" title="Search pages for this text" id="mw-searchButton" class="searchButton mw-fallbackSearchButton"';
const GO_ATTRIBUTES = 'name="go" title="Go to a page with this exact name if it exists" id="searchButton" class="searchButton"';

/**
 * @type {SearchData}
 */
const searchBoxData = {
	'form-action': '/w/index.php',
	'form-id': 'searchform',
	'is-primary': false,
	class: 'vector-search-show-thumbnail',
	'html-user-language-attributes': htmlUserLanguageAttributes,
	'msg-search': 'Search',
	'html-input': `<input ${INPUT_ATTRIBUTES}>`,
	'page-title': 'Special:Search',
	'html-input-attributes': INPUT_ATTRIBUTES,
	'html-button-fulltext-attributes': FULL_TEXT_ATTRIBUTES,
	'msg-searchbutton': 'Search',
	'msg-searcharticle': 'Go',
	'html-button-go-attributes': GO_ATTRIBUTES,
	'html-button-search-fallback': `<input type="submit" ${FULL_TEXT_ATTRIBUTES} value="Search" />`,
	'html-button-search': `<input type="submit" ${GO_ATTRIBUTES} value="Go">`
};

/**
 * @type {SearchData}
 */
const searchBoxDataWithCollapsing = Object.assign( {}, searchBoxData, {
	class: `${searchBoxData.class} vector-search-box-collapses`,
	'is-collapsible': true,
	'data-collapse-icon': {
		icon: 'wikimedia-search',
		'is-quiet': true,
		class: 'search-toggle',
		href: '/wiki/Special:Search',
		label: 'Search'
	}
} );

const SEARCH_TEMPLATE_PARTIALS = {
	Button
};

export {
	SEARCH_TEMPLATE_PARTIALS,
	searchBoxTemplate,
	searchBoxDataWithCollapsing,
	searchBoxData
};
