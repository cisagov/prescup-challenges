/* global RestResult, SearchResult */

/**
 * @typedef {Object} UrlParams
 * @param {string} title
 * @param {string} fulltext
 */

/**
 * @callback generateUrl
 * @param {RestResult|SearchResult|string} searchResult
 * @param {UrlParams} [params]
 * @param {string} [articlePath]
 * @return {string}
 */

/**
 * @typedef {Object} UrlGenerator
 * @property {generateUrl} generateUrl
 */

/**
 * Generates URLs for suggestions like those in MediaWiki's mediawiki.searchSuggest implementation.
 *
 * @param {MwMap} config
 * @return {UrlGenerator}
 */
function urlGenerator( config ) {
	// TODO: This is a placeholder for enabling customization of the URL generator.
	// wgVectorSearchUrlGenerator has not been defined as a config variable yet.
	const customGenerator = config.get( 'wgVectorSearchUrlGenerator' );
	return customGenerator || {
		/**
		 * @type {generateUrl}
		 */
		generateUrl(
			suggestion,
			params = {
				title: 'Special:Search'
			},
			articlePath = config.get( 'wgScript' )
		) {
			if ( typeof suggestion !== 'string' ) {
				suggestion = suggestion.title;
			} else {
				// Add `fulltext` query param to search within pages and for navigation
				// to the search results page (prevents being redirected to a certain
				// article).
				// @ts-ignore
				params.fulltext = '1';
			}

			return articlePath + '?' + $.param( $.extend( {}, params, { search: suggestion } ) );
		}
	};
}

/** @module urlGenerator */
module.exports = urlGenerator;
