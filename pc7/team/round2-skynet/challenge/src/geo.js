const { faker } = require('@faker-js/faker');
const geolib = require('geolib');

function getBBoxFromCoords([ bottomLeftLat, bottomLeftLong ], [ topRightLat, topRightLong ]) {
  return [
    bottomLeftLat,
    bottomLeftLong,
    topRightLat,
    topRightLong,
  ];
}

const BOUND_BOXES = {
  'USA' : [ -125, 25.5, 67.5, 48 ],
  
  'TORONTO' : getBBoxFromCoords([ 43.682, -79.509 ], [ 43.718, -79.374 ]),

  'DENVER' : getBBoxFromCoords([ 39.65, -105.08 ], [ 39.96, -104.92 ]),
  'LOS_ANGELES' : getBBoxFromCoords([ 33.873, -118.285], [ 34.120, -117.824 ]),
  'ATLANTA': getBBoxFromCoords([ 33.698, - 84.429 ], [ 33.845, -84.259 ]),
  'PHOENIX' : getBBoxFromCoords([ 33.407, - 112.289 ], [ 33.668, -112.115]),
  'BUFFALO' : getBBoxFromCoords([ 42.873, -78.873 ], [ 42.897, -78.854 ]),
  'BOSTON' : getBBoxFromCoords([ 42.337, -71.132 ], [ 42.415, -71.063 ]),
  'ANCHORAGE' : getBBoxFromCoords([ 61.174, -149.886 ], [ 61.198, -149.868 ]),
  'PORTLAND' : getBBoxFromCoords([ 45.492, -122.656 ], [ 45.535, -122.620 ]),
  'ALBUQUERQUE' : getBBoxFromCoords([ 35.076, -106.658 ], [ 35.135, -106.619 ]),
  'ORLANDO' : getBBoxFromCoords([ 28.526, -81.401 ], [ 28.553, -81.377 ]),
}

function getRandomCoordsInBox([ minLat, minLong, maxLat, maxLong ]) {
  const lat = faker.number.float({ min : minLat, max : maxLat});
  const long = faker.number.float({ min : minLong, max : maxLong});
  return [ lat, long ];
}

function degreeToVector(degrees) {
  const radians = degrees * (Math.PI / 180);
  return {
    x: Math.sin(radians),
    y: Math.cos(radians)
  };
}

function computeDestination(coord, dir, distance) {
  const bearing = (Math.atan2(dir.x, dir.y) * 180 / Math.PI);

  const { latitude, longitude } = geolib.computeDestinationPoint(
    { latitude : coord[0], longitude: coord[1] },
    distance,
    bearing,
  );

  return [ latitude, longitude ];
}

module.exports.BOUND_BOXES = BOUND_BOXES;
module.exports.getRandomCoordsInBox = getRandomCoordsInBox;
module.exports.degreeToVector = degreeToVector;
module.exports.computeDestination = computeDestination;