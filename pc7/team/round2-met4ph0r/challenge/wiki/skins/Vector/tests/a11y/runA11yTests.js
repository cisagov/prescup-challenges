/* eslint-disable no-console */
// @ts-nocheck
const fs = require( 'fs' );
const fetch = require( 'node-fetch' );
const path = require( 'path' );
const pa11y = require( 'pa11y' );
const { program } = require( 'commander' );

const htmlReporter = require( path.resolve( __dirname, './reporter/reporter.js' ) );
const config = require( path.resolve( __dirname, 'a11y.config.js' ) );

/**
 *  Delete and recreate the report directory
 */
function resetReportDir() {
	// Delete and create report directory
	if ( fs.existsSync( config.reportDir ) ) {
		fs.rmSync( config.reportDir, { recursive: true } );
	}
	fs.mkdirSync( config.reportDir, { recursive: true } );
}

/**
 *  Log test results to Graphite
 *
 * @param {string} namespace
 * @param {string} name
 * @param {number} count
 * @return {Promise<any>}
 */
function sendMetrics( namespace, name, count ) {
	const metricPrefix = 'ci_a11y';
	const url = `${process.env.WMF_JENKINS_BEACON_URL}${metricPrefix}.${namespace}.${name}=${count}c`;
	return fetch( url );
}

/**
 *  Run pa11y on tests specified by the config.
 *
 * @param {Object} opts
 */
async function runTests( opts ) {
	if ( !process.env.MW_SERVER ||
		!process.env.MEDIAWIKI_USER ||
		!process.env.MEDIAWIKI_PASSWORD ) {
		throw new Error( 'Missing env variables' );
	}

	const tests = config.tests;
	const allValidTests = tests.filter( ( test ) => test.name ).length === tests.length;
	if ( !allValidTests ) {
		throw new Error( 'Config missing test name' );
	}

	const canLogResults = process.env.WMF_JENKINS_BEACON_URL && config.namespace;
	if ( opts.logResults && !canLogResults ) {
		throw new Error( 'Unable to log results, missing config or env variables' );
	}

	resetReportDir();

	const testPromises = tests.map( ( test ) => {
		const { url, name, ...testOptions } = test;
		const options = { ...config.defaults, ...testOptions };
		// Automatically enable screen capture for every test;
		options.screenCapture = `${config.reportDir}/${name}.png`;

		return pa11y( url, options ).then( ( testResult ) => {
			testResult.name = name;
			return testResult;
		} );
	} );

	// Run tests against multiple URLs
	const results = await Promise.all( testPromises ); // eslint-disable-line
	results.forEach( async ( testResult ) => {
		const name = testResult.name;
		const errorNum = testResult.issues.filter( ( issue ) => issue.type === 'error' ).length;
		const warningNum = testResult.issues.filter( ( issue ) => issue.type === 'warning' ).length;
		const noticeNum = testResult.issues.filter( ( issue ) => issue.type === 'notice' ).length;

		// Log results summary to console
		if ( !opts.silent ) {
			console.log( `'${name}'- ${errorNum} errors, ${warningNum} warnings, ${noticeNum} notices` );
		}

		// Send data to Graphite
		// WMF_JENKINS_BEACON_URL is only defined in CI env
		if ( opts.logResults && canLogResults ) {
			await sendMetrics( config.namespace, testResult.name, errorNum )
				.then( ( response ) => {
					if ( response.ok ) {
						console.log( `'${name}' results logged successfully` );
					} else {
						console.error( `Failed to log '${name}' results` );
					}
				} );
		}

		// Save in html report
		const html = await htmlReporter.results( testResult );
		fs.promises.writeFile( `${config.reportDir}/report-${name}.html`, html, 'utf8' );
		// Save in json report
		fs.promises.writeFile( `${config.reportDir}/report-${name}.json`, JSON.stringify( testResult, null, '  ' ), 'utf8' );
	} );
}

function setupCLI() {
	program
		.option( '-s, --silent', 'avoids logging results summary to console', false )
		.option( '-l, --logResults', 'log a11y results to Graphite, should only be used with --env ci', false )
		.action( ( opts ) => {
			runTests( opts );
		} );

	program.parse();
}

setupCLI();
