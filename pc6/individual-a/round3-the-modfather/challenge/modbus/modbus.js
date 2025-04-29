'use strict'
const crypto = require('crypto');

const net = require('net')
const modbus = require('jsmodbus')
const netServer = new net.Server()
const holding = Buffer.alloc(10000)
const server = new modbus.server.TCP(netServer, {
    holding: holding
    /* Set the buffer options to undefined to use the events */
    /* coils: undefined */
    /* discrete: undefined */
    /* holding: undefined */
    /* input: undefined */
})

server.on('connection', function (client) {
    console.log('New Connection from ' + client.socket.remoteAddress)
})

//Change the values to random values every 5 seconds
setInterval(() => {
    let x = crypto.randomInt(0, 2)
    server.coils.writeUInt16LE(x, 0)  //Make one boolean always true
    server.discrete.writeUInt16LE(x == 0 ? 1 : 0, 0)

    server.holding.writeUInt16BE(crypto.randomInt(0, 0xffff + 1), 0)
    server.holding.writeUInt16BE(crypto.randomInt(0, 0xffff + 1), 8)

    server.input.writeUInt16BE(crypto.randomInt(0, 0xffff + 1), 0)
    server.input.writeUInt16BE(crypto.randomInt(0, 0xffff + 1), 8)
    // console.log(server.coils)
}, 15000);

console.log("Listening on port " + (process.argv[2] || 8880))
netServer.listen(process.argv[2] || 8880)
