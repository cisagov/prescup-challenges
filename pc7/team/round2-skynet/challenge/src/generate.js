#!/usr/bin/env node

const fs = require('fs');
const crypto = require('crypto');
const { faker } = require('@faker-js/faker');
const _ = require('lodash');
const moment = require('moment-timezone');

const Device = require('./Device.js');
const { BOUND_BOXES } = require('./geo.js');
const { dataToBuffer } = require('./convert.js');

// Must match server.js SECRET_MAC
const SECRET = Buffer.from('0123456789abcdef', 'utf8');

// Must match server.js affine constants
const AFFINE_A = 5;      // odd
const AFFINE_B = 0x22;   // 0..255

function affineEncode(buf) {
  const out = Buffer.alloc(buf.length);
  for (let i = 0; i < buf.length; i++) {
    out[i] = (AFFINE_A * buf[i] + AFFINE_B) & 0xff;
  }
  return out;
}

function u32be(n) {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(n >>> 0);
  return b;
}

function prefixMac(secret, msg) {
  return crypto
    .createHash('sha256')
    .update(Buffer.concat([secret, msg]))
    .digest();
}

if (process.argv.length < 4) {
  console.error('Usage: generate.js <output_filepath> <seed>');
  process.exit(1);
}

const outputFilePath = process.argv[2];
const seedValue = parseInt(process.argv[3], 10);

if (isNaN(seedValue)) {
  console.error('Error: seed must be an integer.');
  process.exit(1);
}

function main() {
  faker.seed(seedValue);

  const START_DATE = moment('2025-01-5', 'YYYY-MM-DD');

  const devices = [
    new Device('Sky Voyager', BOUND_BOXES.DENVER, START_DATE),
    new Device('Aero Scout', BOUND_BOXES.BUFFALO, START_DATE, { direction: 153 }),
    new Device('Cloud Chaser', BOUND_BOXES.TORONTO, START_DATE),
    new Device('Hawk Eye', BOUND_BOXES.ATLANTA, START_DATE, { direction: 56 }),
    new Device('Wind Rider', BOUND_BOXES.PHOENIX, START_DATE, { direction: 43, duration: 25, speed: 13 }),
    new Device('Falcon Wing', BOUND_BOXES.LOS_ANGELES, START_DATE),
    new Device('Nimbus Explorer', BOUND_BOXES.ORLANDO, START_DATE, { direction: 278 }),
    new Device('Storm Tracker', BOUND_BOXES.BOSTON, START_DATE, { duration: 28, speed: 3 }),
    new Device('Eagle Glide', BOUND_BOXES.ANCHORAGE, START_DATE),
    new Device('Zephyr Drone', BOUND_BOXES.PORTLAND, START_DATE),
    new Device('Strato Flyer', BOUND_BOXES.ALBUQUERQUE, START_DATE, { direction: 333 }),
  ];

  const tracks = _.map(devices, (device) => device.fly());

  // Optional debug prints (kept from your .bak)
  const maxDistanceDevice = _.maxBy(devices, (device) => device.totalDistance);
  console.log(`Device with the largest totalDistance: ${maxDistanceDevice.name}, Distance: ${maxDistanceDevice.totalDistance}`);

  const maxDurationDevice = _.maxBy(devices, (device) => device.duration);
  console.log(`Device with the longest duration: ${maxDurationDevice.name}, Duration: ${maxDurationDevice.duration}`);

  // ---- NEW WRAP FORMAT ----
  // 1) build plaintext coords payload (your original format)
  const payload = dataToBuffer(tracks);

  // 2) compute payload length
  const payloadLen = payload.length;

  // 3) compute MAC over plaintext payload
  const mac = prefixMac(SECRET, payload);

  // 4) affine-encode the payload bytes
  const encodedPayload = affineEncode(payload);

  // 5) write final file: [encoded_payload][payload_len][mac]
  const finalBuf = Buffer.concat([encodedPayload, u32be(payloadLen), mac]);
  fs.writeFileSync(outputFilePath, finalBuf);

  console.log(`Wrapped binary file has been saved to ${outputFilePath}`);
}

main();
