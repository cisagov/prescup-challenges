import mustache from 'mustache';
import { menuTemplate, defaultMenu } from './Menu.stories.data';
import '../resources/skins.vector.styles/Menu.less';

export default {
	title: 'Menu'
};

export const menu = () => mustache.render(
	menuTemplate,
	defaultMenu
);
