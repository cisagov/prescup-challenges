import sidebarTemplate from '!!raw-loader!../includes/templates/Sidebar.mustache';
import sidebarLegacyTemplate from '!!raw-loader!../includes/templates/LegacySidebar.mustache';
import { vectorMenuTemplate } from './MenuDropdown.stories.data';
import { PORTALS } from './MenuPortal.stories.data';

const SIDEBAR_BEFORE_OUTPUT_HOOKINFO = `Beware: Portals can be added, removed or reordered using
SidebarBeforeOutput hook as in this example.`;

export { sidebarTemplate, sidebarLegacyTemplate };

export const SIDEBAR_TEMPLATE_PARTIALS = {
	Menu: vectorMenuTemplate
};

export const OPT_OUT_DATA = {
	'data-emphasized-sidebar-action': {
		href: '#',
		'msg-vector-opt-out': 'Switch to old look',
		'msg-vector-opt-out-tooltip': 'Change your settings to go back to the old look of the skin (legacy Vector)'
	}
};

export const SIDEBAR_DATA = {
	withNoPortals: {
		'array-portlets-rest': []
	},
	withPortals: {
		'data-portlets-first': PORTALS.navigation,
		'array-portlets-rest': [
			PORTALS.toolbox,
			PORTALS.otherProjects
		],
		'data-portals-languages': PORTALS.langlinks
	},
	withoutLogo: {
		'data-portals-languages': PORTALS.langlinks,
		'array-portals-first': PORTALS.navigation,
		'array-portlets-rest': [
			PORTALS.toolbox,
			PORTALS.otherProjects
		]
	},
	thirdParty: {
		'array-portlets-rest': [
			PORTALS.toolbox,
			PORTALS.navigation,
			{
				'html-portal-content': SIDEBAR_BEFORE_OUTPUT_HOOKINFO
			}
		]
	}
};
