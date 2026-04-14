import mustache from 'mustache';
import template from '!!raw-loader!../includes/Skins/history.mustache';

import { withAnnotation } from './utils';

export default {
	title: 'Last modified'
};

export const lastModifiedBar = () =>
	withAnnotation( mustache.render( template, {
		historyIconClass: 'last-modified-bar__icon mw-ui-icon mw-ui-icon-mw-ui-icon-small mw-ui-icon-wikimedia-history-base20',
		arrowIconClass: 'mw-ui-icon mw-ui-icon-small mw-ui-icon-mf-expand-gray mf-mw-ui-icon-rotate-anti-clockwise indicator mw-ui-icon-mf-arrow-gray',
		text: 'Last edited on 20 January 2020, at 18:38',
		href: "#/wiki/Special:History/Username",
		'data-user-name': 'Username',
		'data-user-gender': 'female',
		timestamp: '1579545499'
	} ), 'FIXME: Last modified bar currently requires footer element to be styled correctly.', 10 );

export const lastModifiedBarActive = () => {
	const html = mustache.render( template, {
			historyIconClass: 'last-modified-bar__icon mw-ui-icon mw-ui-icon-mw-ui-icon-small mw-ui-icon-wikimedia-history-base20',
			arrowIconClass: 'mw-ui-icon mw-ui-icon-small mw-ui-icon-mf-expand-gray mf-mw-ui-icon-rotate-anti-clockwise indicator mw-ui-icon-mf-arrow-gray',
			text: 'Last edited on 20 January 2020, at 18:38',
			href: "#/wiki/Special:History/Username",
			'data-user-name': 'Username',
			'data-user-gender': 'female',
			timestamp: '1579545499'
		} ),
		node = document.createElement( 'div' );
	node.innerHTML = html;
	node.firstChild.classList.add( 'active' );

	node.querySelector( '.last-modified-bar__text' ).outerHTML = `<span class="last-modified-bar__text">
		<a href="#">Last edited 57 seconds ago</a> by <a href="#">Username</a></span>`;
	// invert icons
	node.querySelector( '.mw-ui-icon-wikimedia-history-base20' ).classList.add(
		'mw-ui-icon-wikimedia-history-invert'
	);
	node.querySelector( '.mw-ui-icon-mf-expand-gray' ).classList.add(
		'mw-ui-icon-mf-expand-invert'
	);
	return withAnnotation( node.innerHTML, 'FIXME: Not possible to render active state with template.', 10 );
};
