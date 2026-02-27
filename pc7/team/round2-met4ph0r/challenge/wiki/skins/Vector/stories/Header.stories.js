import mustache from 'mustache';
import { HEADER_TEMPLATE_DATA, HEADER_TEMPLATE_PARTIALS,
	headerTemplate } from './Header.stories.data';
import '../resources/skins.vector.styles/components/Header.less';

export default {
	title: 'Header'
};

export const header = () => mustache.render(
	headerTemplate,
	HEADER_TEMPLATE_DATA,
	HEADER_TEMPLATE_PARTIALS
);
