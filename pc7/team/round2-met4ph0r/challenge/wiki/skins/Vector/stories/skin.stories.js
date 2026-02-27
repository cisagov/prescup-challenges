import mustache from 'mustache';
import '../resources/common/common.less';
import './skin.less';
import legacySkinTemplate from '!!raw-loader!../includes/templates/skin-legacy.mustache';
import {
	LEGACY_TEMPLATE_DATA,
	NAVIGATION_TEMPLATE_DATA,
	TEMPLATE_PARTIALS
} from './skin.stories.data';

export default {
	title: 'Skin'
};

const vectorLegacyLoggedOutBody = () => mustache.render(
	legacySkinTemplate,
	Object.assign(
		{},
		LEGACY_TEMPLATE_DATA,
		NAVIGATION_TEMPLATE_DATA.loggedOutWithVariants
	),
	TEMPLATE_PARTIALS
);

const vectorLegacyLoggedInBody = () => mustache.render(
	legacySkinTemplate,
	Object.assign(
		{},
		LEGACY_TEMPLATE_DATA,
		NAVIGATION_TEMPLATE_DATA.loggedInWithMoreActions
	),
	TEMPLATE_PARTIALS
);

export const vectorLegacyLoggedOut = () =>
	`<div class="skin-vector-legacy">${vectorLegacyLoggedOutBody()}</div>`;

export const vectorLegacyLoggedIn = () =>
	`<div class="skin-vector-legacy">${vectorLegacyLoggedInBody()}</div>`;
