const { OPCUAClient, makeBrowsePath, AttributeIds, resolveNodeId, TimestampsToReturn } = require("node-opcua");
const async = require("async");
const { exit } = require("process");

const winston = require('winston');
const { combine, timestamp, json, errors } = winston.format;

const logger = winston.createLogger({
    level: 'info',
    format: combine(errors({ stack: true }), timestamp(), json()),
    transports: [new winston.transports.Console({ stderrLevels: ['error', 'warn', 'info'] })],
});

let sessionDetails;

if (process.argv[2]) {  // If any value passed, try to provide login details
    sessionDetails = { userName: "user", password: "tartans" }
    logger.info("Using username/password")
}
else{
    logger.info("Not using username/password; provide any value as an argument to use auth")
}


const endpointUrl = "opc.tcp://123.45.67.89:8080";
logger.info("Attempting to connect to " + endpointUrl)
const client = new OPCUAClient({
    endpointMustExist: false
});

client.on("backoff", (retry, delay) => {
    if (retry >= 3) {
        logger.error("Failed to connect...")
        exit(-1)
    }
    logger.info("Still trying to connect to " + endpointUrl + " : retry =" + retry + " next attempt in " + (delay / 1000) + " seconds")
}
);

let the_session;

async.series(
    [
        // step 1 : connect to
        function (callback) {
            client.connect(endpointUrl, function (err) {
                if (err) {
                    logger.error("Cannot connect to endpoint :", endpointUrl);
                } else {
                    logger.info("Connected !");
                }
                callback(err);
            });
        },

        // step 2 : createSession
        function (callback) {
            client.createSession(sessionDetails, function (err, session) {
                if (err) {
                    return callback(err);
                }
                the_session = session;
                callback();
            });
        },

        // step 3 : read the non-bool variables with readVariableValue
        function (callback) {
            nodes = [
                { name: "holding 1", node: "ns=1;i=1003", attributeId: AttributeIds.Value }, { name: "holding 2", node: "ns=1;i=1004", attributeId: AttributeIds.Value },
                { name: "input 1", node: "ns=1;i=1010", attributeId: AttributeIds.Value }, { name: "input 2", node: "ns=1;i=1011", attributeId: AttributeIds.Value }
            ]

            the_session.readVariableValue(nodes.map(node => node.node), (err, dataValue) => {
                if(!err){
                    for (i = 0; i < nodes.length; i++) {
                        console.log(nodes[i].name + " = " + dataValue[i].value.value + " (" + dataValue[i].statusCode.description + ")");
                    }
                }else{console.log("Reading non-bools failed...")}
                callback(err);
            });
        },
        // step 4 : read the bool variables with readVariableValue
        function (callback) {
            nodes = [
                { name: "coil 1", node: "ns=1;i=1006", attributeId: AttributeIds.Value },
                { name: "discreteInput 1", node: "ns=1;i=1008", attributeId: AttributeIds.Value }
            ]

            the_session.readVariableValue(nodes.map(node => node.node), (err, dataValue) => {
                if(!err){
                    for (i = 0; i < nodes.length; i++) {
                        console.log(nodes[i].name + " = " + dataValue[i].value.value + " (" + dataValue[i].statusCode.description + ")");
                    }
                }else{console.log("Reading bools failed...")}
                callback(err);
            });
        },
        // close session
        function (callback) {
            the_session.close(function (err) {
                if (err) {
                    logger.error("closing session failed ?");
                }
                callback();
            });
        }
    ],
    function (err) {
        if (err) {
            logger.error(" failure ", err);
        } else {
            logger.info("done!");
        }
        client.disconnect(function () { });
    }
);

