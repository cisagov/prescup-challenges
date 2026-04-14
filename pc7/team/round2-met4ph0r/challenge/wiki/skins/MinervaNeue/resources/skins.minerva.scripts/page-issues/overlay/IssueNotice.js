( function ( M ) {
	var
		mobile = M.require( 'mobile.startup' ),
		mfExtend = mobile.mfExtend,
		View = mobile.View;

	/**
	 * IssueNotice
	 *
	 * @class IssueNotice
	 * @extends View
	 *
	 * @param {IssueSummary} props
	 */
	function IssueNotice( props ) {
		View.call( this, props );
	}
	mfExtend( IssueNotice, View, {
		tagName: 'li',
		template: mw.template.get( 'skins.minerva.scripts', 'IssueNotice.mustache' ),
		postRender: function () {
			View.prototype.postRender.apply( this, arguments );
			this.$el.find( '.issue-notice' ).prepend( this.options.issue.icon.$el );
		}
	} );
	module.exports = IssueNotice;

// eslint-disable-next-line no-restricted-properties
}( mw.mobileFrontend ) );
