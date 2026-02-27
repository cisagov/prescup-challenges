( function ( M ) {
	var
		Overlay = M.require( 'mobile.startup' ).Overlay,
		IssueList = require( './IssueList.js' ),
		KEYWORD_ALL_SECTIONS = 'all',
		NS_MAIN = 0,
		NS_TALK = 1,
		NS_CATEGORY = 14;

	/**
	 * Overlay for displaying page issues
	 *
	 * @param {IssueSummary[]} issues list of page issue summaries for display.
	 * @param {string} section
	 * @param {number} namespaceID
	 * @return {Overlay}
	 */
	function pageIssuesOverlay( issues, section, namespaceID ) {
		var overlay,
			// Note only the main namespace is expected to make use of section issues, so the
			// heading will always be minerva-meta-data-issues-section-header regardless of
			// namespace.
			headingText = section === '0' || section === KEYWORD_ALL_SECTIONS ?
				getNamespaceHeadingText( namespaceID ) :
				mw.msg( 'minerva-meta-data-issues-section-header' );

		overlay = new Overlay( {
			className: 'overlay overlay-issues',
			heading: '<strong>' + headingText + '</strong>'
		} );

		overlay.$el.find( '.overlay-content' ).append(
			new IssueList( issues ).$el
		);
		return overlay;
	}

	/**
	 * Obtain a suitable heading for the issues overlay based on the namespace
	 *
	 * @param {number} namespaceID is the namespace to generate heading for
	 * @return {string} heading for overlay
	 */
	function getNamespaceHeadingText( namespaceID ) {
		switch ( namespaceID ) {
			case NS_CATEGORY:
				return mw.msg( 'mobile-frontend-meta-data-issues-categories' );
			case NS_TALK:
				return mw.msg( 'mobile-frontend-meta-data-issues-talk' );
			case NS_MAIN:
				return mw.msg( 'mobile-frontend-meta-data-issues' );
			default:
				return '';
		}
	}

	module.exports = pageIssuesOverlay;

// eslint-disable-next-line no-restricted-properties
}( mw.mobileFrontend ) );
