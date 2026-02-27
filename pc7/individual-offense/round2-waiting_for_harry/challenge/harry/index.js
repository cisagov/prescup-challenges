const { chromium } = require('playwright');
const { setTimeout } = require('node:timers/promises');
const LEADERBOARD_URL = 'https://dodgethecreeps/leaderboard';

(async () => {
  async function launchBrowser() {
    return await chromium.launch({ args: ['--ignore-ssl-errors', '--ignore-certificate-errors'],
    ignoreHTTPSErrors: true, headless : true });
  }

  let browser = await launchBrowser();

  async function getBrowser() {
    if (browser.isConnected()) {
      return browser;
    }
    await setTimeout(10000);
    browser = await launchBrowser();
    return browser;
  }

  async function goToLeaderboard() {
    const browser = await getBrowser();
    const context = await browser.newContext();
    await context.addCookies([ { name : 'flag', value : process.env.FLAG, url : LEADERBOARD_URL } ]);
    const page = await context.newPage();
    await page.goto(LEADERBOARD_URL, { waitUntil: 'load', timeout: 10000 });
    await page.close();
    await context.close();
  }

  while (true) {
    try {
      await goToLeaderboard();
      break;
    } catch (error) {
      console.error('Error occurred while connecting to the server:', error);
      await setTimeout(5000); // Wait for 5 seconds before retrying
      console.log('Retrying to connect to the browser...');
    }
  }
  console.log('Connected to the browser successfully!');
  while (true) {
    console.log('Harry is checking the leaderboard');
    try {
      await goToLeaderboard();
      console.log('Harry checked the leaderboard successfully!');
    } catch (error) {
      console.error('Error occurred while navigating to the leaderboard:', error);
    }
    await setTimeout(5000); // Wait for 5 seconds
  }
})();
