( function ( M ) {
	var
		mobile = M.require( 'mobile.startup' ),
		ToggleList = require( '../../includes/Skins/ToggleList/ToggleList.js' ),
		Icon = mobile.Icon,
		page = mobile.currentPage(),
		/** The top level menu. */
		toolbarSelector = '.page-actions-menu',
		/** The secondary overflow submenu component container. */
		overflowSubmenuSelector = '#page-actions-overflow',
		overflowListSelector = '.toggle-list__list';

	/**
	 * @param {Window} window
	 * @param {Element} toolbar
	 * @return {void}
	 */
	function bind( window, toolbar ) {
		var overflowSubmenu = toolbar.querySelector( overflowSubmenuSelector );
		if ( overflowSubmenu ) {
			ToggleList.bind( window, overflowSubmenu );
		}
	}

	/**
	 * @param {Window} window
	 * @param {Element} toolbar
	 * @return {void}
	 */
	function render( window, toolbar ) {
		var overflowList = toolbar.querySelector( overflowListSelector );
		renderEditButton();
		renderDownloadButton( window, overflowList );
	}

	/**
	 * Initialize page edit action link (#ca-edit)
	 *
	 * Mark the edit link as disabled if the user is not actually able to edit the page for some
	 * reason (e.g. page is protected or user is blocked).
	 *
	 * Note that the link is still clickable, but clicking it will probably open a view-source
	 * form or display an error message, rather than open an edit form.
	 *
	 * FIXME: Review this code as part of T206262
	 *
	 * @ignore
	 */
	function renderEditButton() {
		var
			// FIXME: create a utility method to generate class names instead of
			//       constructing temporary objects. This affects disabledEditIcon,
			//       enabledEditIcon, enabledEditIcon, and disabledClass and
			//       a number of other places in the code base.
			disabledEditIcon = new Icon( {
				name: 'editLock-base20',
				glyphPrefix: 'wikimedia'
			} ),
			enabledEditIcon = new Icon( {
				name: 'edit-base20',
				glyphPrefix: 'wikimedia'
			} ),
			enabledClass = enabledEditIcon.getGlyphClassName(),
			disabledClass = disabledEditIcon.getGlyphClassName();

		if ( mw.config.get( 'wgMinervaReadOnly' ) ) {
			// eslint-disable-next-line no-jquery/no-global-selector
			$( '#ca-edit' )
				.removeClass( enabledClass )
				.addClass( disabledClass );
		}
	}

	/**
	 * Initialize and inject the download button
	 *
	 * There are many restrictions when we can show the download button, this function should handle
	 * all device/os/operating system related checks and if device supports printing it will inject
	 * the Download icon
	 *
	 * @param {Window} window
	 * @param {Element|null} overflowList
	 * @return {void}
	 */
	function renderDownloadButton( window, overflowList ) {
		var downloadPageAction = require( './downloadPageAction.js' ).downloadPageAction,
			$downloadAction = downloadPageAction( page,
				mw.config.get( 'wgMinervaDownloadNamespaces', [] ), window, !!overflowList );

		if ( $downloadAction ) {
			mw.track( 'minerva.downloadAsPDF', {
				action: 'buttonVisible'
			} );
		}
	}

	module.exports = {
		selector: toolbarSelector,
		bind: bind,
		render: render
	};

// eslint-disable-next-line no-restricted-properties
}( mw.mobileFrontend ) );
