/**
 * @param {string} name
 * @return {string}
 */
function makeIcon( name ) {
	return `<span class="mw-ui-icon mw-ui-icon-${name}"></span>`;
}

/**
 * @param {string} msg
 * @param {number} [height=200]
 * @return {string}
 */
const placeholder = ( msg, height ) => {
	return `<div style="width: 100%; height: ${height || 200}px; margin-bottom: 2px;
		font-size: 12px; padding: 8px; box-sizing: border-box;
		display: flex; background: #eee; align-items: center;justify-content: center;">${msg}</div>`;
};

/**
 * @param {string} html
 * @return {string}
 */
const portletAfter = ( html ) => {
	return `<div class="after-portlet after-portlet-tb">${html}</div>`;
};

const htmlUserLanguageAttributes = `dir="ltr" lang="en-GB"`;

/**
 * @param {string} [additionalClassString] to add to the menu class
 * @return {Object}
 */
function helperClassName( additionalClassString = '' ) {
	return { class: additionalClassString };
}

/**
 * @param {string} name of the menu
 * @param {string} htmlItems
 * @param {Object} [additionalData] to add to the menu template data
 * @param {string} [additionalData.class]
 * @return {MenuDefinition}
 */
function helperMakeMenuData( name, htmlItems, additionalData = {} ) {
	let label;
	switch ( name ) {
		case 'personal':
			label = 'Personal tools';
			break;
		default:
			label = 'Menu label';
			break;
	}

	// Handle "class" property separately to ensure it is appended to existing classes
	const additionalClassString = additionalData.class;
	const additionalDataWithoutClass = Object.assign( {}, additionalData );
	delete additionalDataWithoutClass.class;

	return Object.assign( {
		id: `p-${name}`,
		class: `mw-portlet mw-portlet-${name} ${additionalClassString}`,
		label,
		'html-user-language-attributes': htmlUserLanguageAttributes,
		'html-items': htmlItems
	}, additionalDataWithoutClass );
}

export {
	makeIcon,
	placeholder,
	htmlUserLanguageAttributes,
	portletAfter,
	helperClassName,
	helperMakeMenuData
};
