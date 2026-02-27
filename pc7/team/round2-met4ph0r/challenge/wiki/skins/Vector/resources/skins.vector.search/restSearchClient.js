/* global RestResult, SearchResult */
/** @module restSearchClient */

const fetchJson = require( './fetch.js' );
const urlGenerator = require( './urlGenerator.js' );

/**
 * @typedef {Object} RestResponse
 * @property {RestResult[]} pages
 */

/**
 * @typedef {Object} SearchResponse
 * @property {string} query
 * @property {SearchResult[]} results
 */

/**
 * Nullish coalescing operator (??) helper
 *
 * @param {any} a
 * @param {any} b
 * @return {any}
 */
function nullish( a, b ) {
	return ( a !== null && a !== undefined ) ? a : b;
}

/**
 * @param {MwMap} config
 * @param {string} query
 * @param {RestResponse} restResponse
 * @param {boolean} showDescription
 * @return {SearchResponse}
 */
function adaptApiResponse( config, query, restResponse, showDescription ) {
	const urlGeneratorInstance = urlGenerator( config );
	return {
		query,
		results: restResponse.pages.map( ( page, index ) => {
			const thumbnail = page.thumbnail;
			return {
				id: page.id,
				value: page.id || -( index + 1 ),
				label: page.title,
				key: page.key,
				title: page.title,
				description: showDescription ? page.description : undefined,
				url: urlGeneratorInstance.generateUrl( page ),
				thumbnail: thumbnail ? {
					url: thumbnail.url,
					width: nullish( thumbnail.width, undefined ),
					height: nullish( thumbnail.height, undefined )
				} : undefined
			};
		} )
	};
}

/**
 * @typedef {Object} AbortableSearchFetch
 * @property {Promise<SearchResponse>} fetch
 * @property {Function} abort
 */

/**
 * @callback fetchByTitle
 * @param {string} query The search term.
 * @param {string} domain The base URL for the wiki without protocol. Example: 'sr.wikipedia.org'.
 * @param {number} [limit] Maximum number of results.
 * @return {AbortableSearchFetch}
 */

/**
 * @typedef {Object} SearchClient
 * @property {fetchByTitle} fetchByTitle
 */

/**
 * @param {MwMap} config
 * @return {SearchClient}
 */
function restSearchClient( config ) {
	const customClient = config.get( 'wgVectorSearchClient' );
	return customClient || {
		/**
		 * @type {fetchByTitle}
		 */
		fetchByTitle: ( q, domain, limit = 10, showDescription = true ) => {
			const params = { q, limit };
			const url = '//' + domain + config.get( 'wgScriptPath' ) + '/rest.php/v1/search/title?' + $.param( params );
			const result = fetchJson( url, {
				headers: {
					accept: 'application/json'
				}
			} );
			const searchResponsePromise = result.fetch
				.then( ( /** @type {RestResponse} */ res ) => {
					return adaptApiResponse( config, q, res, showDescription );
				} );
			return {
				abort: result.abort,
				fetch: searchResponsePromise
			};
		}
	};
}

module.exports = restSearchClient;
