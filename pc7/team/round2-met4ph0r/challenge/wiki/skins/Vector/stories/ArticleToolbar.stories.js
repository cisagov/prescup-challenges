import mustache from 'mustache';
import { articleToolbarTemplate,
	ARTICLE_TOOLBAR_TEMPLATE_DATA,
	ARTICLE_TOOLBAR_PARTIALS } from './ArticleToolbar.stories.data';
import '../resources/skins.vector.styles/components/ArticleToolbar.less';

export default {
	title: 'ArticleToolbar'
};

export const defaultState = () => mustache.render(
	articleToolbarTemplate,
	ARTICLE_TOOLBAR_TEMPLATE_DATA,
	ARTICLE_TOOLBAR_PARTIALS
);
