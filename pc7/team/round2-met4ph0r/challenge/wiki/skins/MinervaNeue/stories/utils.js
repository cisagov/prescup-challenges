/**
 *
 * @param {string} msg to display
 * @param {number} height of placeholder
 * @return {string}
 */
const placeholder = ( msg, height ) => {
	return `<div style="width: 100%; height: ${height || 200}px; margin-bottom: 2px;
		font-size: 1.4em; padding: 8px;
		display: flex; background: #eaecf0; align-items: center; justify-content: center;">${msg}</div>`;
};

/**
 *
 * @param {string} story to describe.
 * @param {string} annotation to annotate story with.
 * @param {number} height of placeholder
 * @return {string}
 */
const withAnnotation = ( story, annotation, height ) => {
	const node = document.createElement( 'div' );
	node.innerHTML = placeholder( annotation, height ) + story;
	return node.outerHTML;
};

export { placeholder, withAnnotation };
