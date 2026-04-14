import mustache from 'mustache';
import '../resources/skins.vector.styles/components/StickyHeader.less';

import { template, data,
	STICKY_HEADER_TEMPLATE_PARTIALS } from './StickyHeader.stories.data';

export default {
	title: 'StickyHeader'
};

export const stickyHeader = () => mustache.render(
	template, data, STICKY_HEADER_TEMPLATE_PARTIALS
);
