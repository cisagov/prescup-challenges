// convert.js
const fs = require('fs');
const _ = require('lodash');

function dataToBuffer(tracks) {
  const trackCountBuffer = Buffer.alloc(4);
  trackCountBuffer.writeUInt32BE(tracks.length);

  const binaryTrackData = _.map(tracks, ({ name, points }) => {
    const nameBuf = Buffer.from(name, 'utf-8');
    const nameLenBuf = Buffer.alloc(4);
    nameLenBuf.writeUInt32BE(nameBuf.length);

    const pointCountBuf = Buffer.alloc(4);
    pointCountBuf.writeUInt32BE(points.length);

    const pointBufs = _.map(points, ({ timestamp, coord }) => {
      const [lat, lon] = coord;

      const tsBuf = Buffer.alloc(8);
      tsBuf.writeBigUInt64BE(BigInt(timestamp.getTime()));

      const latBuf = Buffer.alloc(8);
      latBuf.writeDoubleBE(lat);

      const lonBuf = Buffer.alloc(8);
      lonBuf.writeDoubleBE(lon);

      return Buffer.concat([tsBuf, latBuf, lonBuf]);
    });

    return Buffer.concat([nameLenBuf, nameBuf, pointCountBuf, Buffer.concat(pointBufs)]);
  });

  return Buffer.concat([trackCountBuffer, ...binaryTrackData]);
}

function dataToBinary(filePath, tracks) {
  const buf = dataToBuffer(tracks);
  fs.writeFileSync(filePath, buf);
  console.log(`Binary file has been saved to ${filePath}`);
}

module.exports = { dataToBuffer, dataToBinary };
