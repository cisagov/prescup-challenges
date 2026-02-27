import { placeholder, htmlUserLanguageAttributes,
	makeIcon, portletAfter } from './utils';

/**
 * @type {MenuDefinition}
 */
export const languageData = {
	id: 'p-lang-btn',
	'is-dropdown': true,
	// both classes needed for this to render correctly
	class: 'mw-portlet-lang vector-menu-dropdown',
	// mw-interlanguage-selector must be present to operate in ULS mode.
	// icon classes and button classes
	'checkbox-class': 'mw-interlanguage-selector',
	'html-vector-heading-icon': makeIcon( 'wikimedia-language' ),
	'heading-class': 'mw-ui-button mw-ui-quiet',
	'html-tooltip': 'A message tooltip-p-lang must exist for this to appear',
	label: '10 languages',
	'html-user-language-attributes': htmlUserLanguageAttributes,
	'html-items': `
	<li class="interlanguage-link interwiki-ace">
		<a href="https://ace.wikipedia.org/wiki/Seupanyo"
			title="Seupanyo – Achinese" lang="ace" hreflang="ace" class="interlanguage-link-target">Acèh</a>
			</li><li class="interlanguage-link interwiki-kbd"><a href="https://kbd.wikipedia.org/wiki/%D0%AD%D1%81%D0%BF%D0%B0%D0%BD%D0%B8%D1%8D" title="Эспаниэ – Kabardian" lang="kbd" hreflang="kbd" class="interlanguage-link-target">Адыгэбзэ</a></li><li class="interlanguage-link interwiki-ady"><a href="https://ady.wikipedia.org/wiki/%D0%98%D1%81%D0%BF%D0%B0%D0%BD%D0%B8%D0%B5" title="Испание – Adyghe" lang="ady" hreflang="ady" class="interlanguage-link-target">Адыгабзэ</a></li><li class="interlanguage-link interwiki-af"><a href="https://af.wikipedia.org/wiki/Spanje" title="Spanje – Afrikaans" lang="af" hreflang="af" class="interlanguage-link-target">Afrikaans</a></li><li class="interlanguage-link interwiki-ak"><a href="https://ak.wikipedia.org/wiki/Spain" title="Spain – Akan" lang="ak" hreflang="ak" class="interlanguage-link-target">Akan</a></li><li class="interlanguage-link interwiki-als"><a href="https://als.wikipedia.org/wiki/Spanien" title="Spanien – Alemannisch" lang="gsw" hreflang="gsw" class="interlanguage-link-target">Alemannisch</a></li><li class="interlanguage-link interwiki-am"><a href="https://am.wikipedia.org/wiki/%E1%8A%A5%E1%88%B5%E1%8D%93%E1%8A%95%E1%8B%AB" title="እስፓንያ – Amharic" lang="am" hreflang="am" class="interlanguage-link-target">አማርኛ</a></li><li class="interlanguage-link interwiki-ang"><a href="https://ang.wikipedia.org/wiki/Sp%C4%93onland" title="Spēonland – Old English" lang="ang" hreflang="ang" class="interlanguage-link-target">Ænglisc</a></li><li class="interlanguage-link interwiki-ab"><a href="https://ab.wikipedia.org/wiki/%D0%98%D1%81%D0%BF%D0%B0%D0%BD%D0%B8%D0%B0" title="Испаниа – Abkhazian" lang="ab" hreflang="ab" class="interlanguage-link-target">Аԥсшәа</a></li><li class="interlanguage-link interwiki-ar badge-Q17437798 badge-goodarticle" title="good article"><a href="https://ar.wikipedia.org/wiki/%D8%A5%D8%B3%D8%A8%D8%A7%D9%86%D9%8A%D8%A7" title="إسبانيا – Arabic" lang="ar" hreflang="ar" class="interlanguage-link-target">العربية</a></li>
`,
	'html-after-portal': portletAfter(
		`<span class="wb-langlinks-edit wb-langlinks-link"><a href="https://www.wikidata.org/wiki/Special:EntityPage/Q29#sitelinks-wikipedia" title="Edit interlanguage links (provided by WikiBase extension)" class="wbc-editpage">Edit links</a></span></div>
${placeholder( `<p>Further hook output possible (lang)</p>`, 60 )}`
	)
};
