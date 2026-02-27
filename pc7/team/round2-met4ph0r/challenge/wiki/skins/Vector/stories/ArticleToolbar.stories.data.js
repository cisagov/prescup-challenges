import articleToolbarTemplate from '!!raw-loader!../includes/templates/ArticleToolbar.mustache';
import { namespaceTabsData, pageActionsData } from './MenuTabs.stories.data';
import { menuTemplate } from './Menu.stories.data';

const ARTICLE_TOOLBAR_TEMPLATE_DATA = {
	'data-portlets': {
		'data-views': pageActionsData,
		'data-namespaces': namespaceTabsData
	}
};

const ARTICLE_TOOLBAR_TEMPLATE_DATA_LEGACY = {
	'data-portlets': {
		'data-views': Object.assign( {}, pageActionsData, {
			class: 'vector-menu-tabs-legacy'
		} ),
		'data-namespaces': Object.assign( {}, namespaceTabsData, {
			class: 'vector-menu-tabs-legacy'
		} )
	}
};

const ARTICLE_TOOLBAR_PARTIALS = {
	Menu: menuTemplate
};

export { articleToolbarTemplate, ARTICLE_TOOLBAR_TEMPLATE_DATA,
	ARTICLE_TOOLBAR_TEMPLATE_DATA_LEGACY, ARTICLE_TOOLBAR_PARTIALS };
