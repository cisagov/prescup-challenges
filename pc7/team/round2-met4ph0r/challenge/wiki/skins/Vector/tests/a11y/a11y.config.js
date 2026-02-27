// @ts-nocheck
const path = require( 'path' );

const testData = {
	baseUrl: process.env.MW_SERVER,
	pageUrl: '/wiki/Polar_bear?useskin=vector-2022&tableofcontents=1',
	loginUser: process.env.MEDIAWIKI_USER,
	loginPassword: process.env.MEDIAWIKI_PASSWORD
};

module.exports = {
	// LOG_DIR set in CI, used to make report files available in Jenkins
	reportDir: process.env.LOG_DIR || path.join( process.cwd(), 'a11y/' ),
	namespace: 'Vector',
	defaults: {
		viewport: {
			width: 1200,
			height: 1080
		},
		runners: [
			'axe',
			'htmlcs'
		],
		includeWarnings: true,
		includeNotices: true,
		hideElements: '#bodyContent, #siteNotice, #mwe-pt-toolbar, #centralnotice, #centralnotice_testbanner',
		chromeLaunchConfig: {
			headless: true,
			args: [
				'--no-sandbox',
				'--disable-setuid-sandbox'
			]
		}
	},
	tests: [
		{
			name: 'default',
			url: testData.baseUrl + testData.pageUrl,
			actions: [
				'check field #mw-sidebar-checkbox' // Open main menu
			]
		},
		{
			name: 'logged_in',
			url: testData.baseUrl + testData.pageUrl,
			wait: '500',
			actions: [
				'click #p-personal-checkbox',
				'wait for .vector-user-menu-login a to be visible',
				'click .vector-user-menu-login a',
				'wait for #wpName1 to be visible',
				'set field #wpName1 to ' + testData.loginUser,
				'set field #wpPassword1 to ' + testData.loginPassword,
				'click #wpLoginAttempt',
				'wait for #pt-userpage-2 to be visible', // Confirm login was successful
				'check field #mw-sidebar-checkbox' // Open main menu
			]
		},
		{
			name: 'search',
			url: testData.baseUrl + testData.pageUrl,
			rootElement: '#p-search',
			wait: '500',
			actions: [
				'click #searchInput',
				'wait for .cdx-text-input__input to be added',
				'set field .cdx-text-input__input to Test'
			]
		}
	]
};
