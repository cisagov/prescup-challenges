import mustache from 'mustache';
import '../resources/skins.vector.styles/LanguageButton.less';
import { vectorMenuTemplate } from './MenuDropdown.stories.data';
import { languageData } from './LanguageButton.stories.data';

export default {
	title: 'LanguageButton'
};

export const languageButton = () => mustache.render( vectorMenuTemplate, languageData );
