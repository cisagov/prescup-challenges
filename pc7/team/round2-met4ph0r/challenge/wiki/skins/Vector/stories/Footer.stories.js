import mustache from 'mustache';
import { FOOTER_TEMPLATE_DATA, FOOTER_TEMPLATE_PARTIALS,
	footerTemplate } from './Footer.stories.data';
import '../resources/skins.vector.styles/Footer.less';

export default {
	title: 'Footer'
};

export const footer = () => mustache.render(
	footerTemplate,
	FOOTER_TEMPLATE_DATA,
	FOOTER_TEMPLATE_PARTIALS
);
