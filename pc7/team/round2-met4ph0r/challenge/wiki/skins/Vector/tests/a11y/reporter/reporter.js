// @ts-nocheck
'use strict';

const fs = require( 'fs' );
const path = require( 'path' );
const mustache = require( 'mustache' );
const reportTemplate = fs.readFileSync( path.resolve( __dirname, 'report.mustache' ), 'utf8' );

const report = module.exports = {};

// Utility function to uppercase the first character of a string
function upperCaseFirst( string ) {
	return string.charAt( 0 ).toUpperCase() + string.slice( 1 );
}

// Pa11y version support
report.supports = '^6.0.0 || ^6.0.0-alpha || ^6.0.0-beta';

// Compile template and output formatted results
report.results = async ( results ) => {
	const messagesByType = results.issues.reduce( ( result, issue ) => {
		if ( result[ issue.type ].indexOf( issue.message ) === -1 ) {
			result[ issue.type ].push( issue.message );
		}
		return result;
	}, { error: [], warning: [], notice: [] } );
	const issuesByMessage = results.issues.reduce( ( result, issue ) => {
		if ( result[ issue.message ] ) {
			result[ issue.message ].push( issue );
		} else {
			result[ issue.message ] = [ issue ];
		}
		return result;
	}, {} );
	const issueData = [ 'error', 'warning', 'notice' ].map( ( type ) => ( {
		type,
		typeLabel: upperCaseFirst( type ) + 's',
		typeCount: messagesByType[ type ].length,
		messages: messagesByType[ type ].map( ( message ) => {
			const firstIssue = issuesByMessage[ message ][ 0 ];
			const hasRunnerExtras = Object.keys( firstIssue.runnerExtras ).length > 0;
			return {
				message,
				issueCount: issuesByMessage[ message ].length,
				runner: firstIssue.runner,
				runnerExtras: hasRunnerExtras ? firstIssue.runnerExtras : false,
				code: firstIssue.code,
				issues: issuesByMessage[ message ]
			};
		} ).sort( ( a, b ) => {
			// Sort messages by number of issues
			return b.issueCount - a.issueCount;
		} )
	} ) );

	return mustache.render( reportTemplate, {
		// The current date
		date: new Date(),

		// Test information
		name: results.name,
		pageUrl: results.pageUrl,

		// Results
		issueData,

		// Issue counts
		errorCount: results.issues.filter( ( issue ) => issue.type === 'error' ).length,
		warningCount: results.issues.filter( ( issue ) => issue.type === 'warning' ).length,
		noticeCount: results.issues.filter( ( issue ) => issue.type === 'notice' ).length
	} );
};

// Output error messages
report.error = ( message ) => {
	return message;
};
