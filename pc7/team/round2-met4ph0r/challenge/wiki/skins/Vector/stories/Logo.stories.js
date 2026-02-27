import mustache from 'mustache';
import { logoTemplate, LOGO_TEMPLATE_DATA } from './Logo.stories.data';
import '../resources/skins.vector.styles/Logo.less';

export default {
	title: 'Logo'
};

export const logo = () => mustache.render(
	logoTemplate,
	LOGO_TEMPLATE_DATA.wordmarkTaglineIcon[ 'data-logos' ]
);

export const logoWordmarkIcon = () => mustache.render(
	logoTemplate,
	LOGO_TEMPLATE_DATA.wordmarkIcon[ 'data-logos' ]
);

export const logoWordmark = () => mustache.render(
	logoTemplate,
	LOGO_TEMPLATE_DATA.wordmarkOnly[ 'data-logos' ]
);

export const noLogo = () => mustache.render(
	logoTemplate,
	LOGO_TEMPLATE_DATA.noLogo
);
