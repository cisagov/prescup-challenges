/**
 * Copies interwiki links to sidebar
 *
 * Temporary solution to T287206, can be removed when the new ULS built in Vue.js
 * has been released and contains this
 */
function addInterwikiLinkToSidebar() {
	// eslint-disable-next-line no-jquery/no-global-selector
	var $editLink = $( '#p-lang-btn .wbc-editpage' );
	if ( $editLink.length ) {
		// Use title attribute for link text
		$editLink.text( $editLink.attr( 'title' ) || '' );
		var $li = $( '<li>' )
			// If the Wikibase code runs last, this class is required so it matches the selector @:
			// https://gerrit.wikimedia.org/g/mediawiki/extensions/Wikibase/+/f2e96e1b08fc5ae2e2e92f05d5eda137dc6b1bc8/client/resources/wikibase.client.linkitem.init.js#82
			.addClass( 'wb-langlinks-link' )
			.append( $editLink );
		$li.appendTo( '#p-tb ul' );
	}
}

/**
 * Initialize the language button.
 */
module.exports = function () {
	addInterwikiLinkToSidebar();
};
