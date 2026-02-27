import mustache from 'mustache';
import '../resources/skins.vector.styles/SearchBox.less';

import { searchBoxData, searchBoxDataWithCollapsing, searchBoxTemplate,
	SEARCH_TEMPLATE_PARTIALS
} from './SearchBox.stories.data';

export default {
	title: 'SearchBox'
};

export const searchBoxWithoutCollapsing = () => `
	${mustache.render( searchBoxTemplate, searchBoxData, SEARCH_TEMPLATE_PARTIALS )}
`;

export const searchBoxWithCollapsing = () => `
	${mustache.render( searchBoxTemplate, searchBoxDataWithCollapsing, SEARCH_TEMPLATE_PARTIALS )}
`;
