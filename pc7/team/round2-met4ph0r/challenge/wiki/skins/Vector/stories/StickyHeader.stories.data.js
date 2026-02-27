import template from '!!raw-loader!../includes/templates/StickyHeader.mustache';
import Button from '!!raw-loader!../includes/templates/Button.mustache';
import { searchBoxData } from './SearchBox.stories.data';

const NO_ICON = {
	icon: 'none',
	'is-quiet': true,
	class: 'sticky-header-icon'
};

const TALK_ICON = {
	icon: 'none',
	'is-quiet': true,
	class: 'sticky-header-icon mw-ui-icon-wikimedia-speechBubbles'
};

const HISTORY_ICON = {
	icon: 'none',
	'is-quiet': true,
	class: 'sticky-header-icon mw-ui-icon-wikimedia-history'
};

const data = {
	title: 'Audre Lorde',
	heading: 'Introduction',
	'data-primary-action': {
		id: 'p-lang-btn-sticky-header',
		class: 'mw-interlanguage-selector',
		'is-quiet': true,
		label: '196 languages',
		'html-vector-button-icon': `<span class="mw-ui-icon mw-ui-icon-wikimedia-language"></span>`
	},
	'data-search': searchBoxData,
	'data-button-start': {
		icon: 'wikimedia-search',
		class: 'vector-sticky-header-search-toggle',
		'is-quiet': true,
		label: 'Search'
	},
	'data-button-end': NO_ICON,
	'data-buttons': [
		TALK_ICON, HISTORY_ICON, NO_ICON, NO_ICON
	]
};

export const STICKY_HEADER_TEMPLATE_PARTIALS = {
	Button
};

export { template, data };
