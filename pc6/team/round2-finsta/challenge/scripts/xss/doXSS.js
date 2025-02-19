const jsdom = require("jsdom");
const { JSDOM } = jsdom;

const http = require("http");

const args = process.argv.slice(2); // Remove the first two elements (node and script path)
let user = 0;
let token = 0;

if (args.length > 1) {
  user = args[0];
  token = args[1];
} else {
  console.error("No command line arguments provided. Need user profile to grab and token for cookie.");
  process.exit(-1);
}

http
    .get(`http://finsta.us/profile/` + user, resp => {
        let data = "";

        // A chunk of data has been recieved.
        resp.on("data", chunk => {
            data += chunk;
        });

        // The whole response has been received. Print out the result.
        resp.on("end", () => {
            let cook = new jsdom.CookieJar();
            cook.setCookie('token=' + token, 'http://finsta.us', {http: false});
            const dom = new JSDOM(data, {
                url: "http://finsta.us/",
                referrer: "http://finsta.us/",
                contentType: "text/html",
                includeNodeLocations: false,
                runScripts: "dangerously",
                cookieJar: cook
                //   storageQuota: 10000000
            });
        });
    })
    .on("error", err => {
        console.log("Error: ", err);
    });