const { faker, th } = require('@faker-js/faker');
const tzLookup = require('tz-lookup');

const { getRandomCoordsInBox, computeDestination, degreeToVector } = require('./geo');

const MIN_SPEED = 10; // Meters per second
const MAX_SPEED = 14; // Meters per second
const MAX_SPEED_DELTA = 0.1; // Meters per second

const MAX_DEGREES = 360;
const MIN_DEGRESS = 0;

const MAX_DIRECTION_DELTA = 5; // Degrees

const MIN_FLIGHT_DURATION = 5; // Minutes
const MAX_FLIGHT_DURATION = 20; // Minutes

const TICKRATE = 5; // Seconds

function drift(curr_val, max_delta, min_val, max_val) {
  const delta = faker.number.float({ min : -max_delta, max : max_delta });
  const next = Math.max(min_val, Math.min(max_val, curr_val + delta));
  return next;
}

class Device {
  constructor(name, box, startDate, { duration, speed, direction } = { }) {
    this.name = name;
    this.coords = getRandomCoordsInBox(box);
    this.direction = direction ||faker.number.int({ min: MIN_DEGRESS, max: MAX_DEGREES });
    this.speed = speed || faker.number.float({ min: MIN_SPEED, max: MAX_SPEED }); // Meters per second
    this.duration = (duration || faker.number.int({ min: MIN_FLIGHT_DURATION, max: MAX_FLIGHT_DURATION })) * 60; // Minutes
    this.totalDistance = 0;

    this.timezone = tzLookup(...this.coords);
    this.startTime = startDate
      .clone()
      .hour(faker.number.int({ min : 10, max : 15 }))
      .minute(faker.number.int({ min : 0, max : 59 }))
      .second(faker.number.int({ min : 0, max : 59 }))
      .tz(this.timezone, true)
    ;
  }

  move(distance) {
    this.coords = computeDestination(this.coords, degreeToVector(this.direction), distance);
    this.totalDistance = parseFloat((this.totalDistance + distance).toFixed(2));
  }

  fly() {
    const currTime = this.startTime.clone();
    let tick = 0;
    const events = [ ];
    while (tick < this.duration) {
      currTime.add(TICKRATE, 'second');
      tick += TICKRATE;

      events.push({
        timestamp : currTime.toDate(),
        coord : this.coords,
      });

      this.speed = drift(this.speed, MAX_SPEED_DELTA, MIN_SPEED, MAX_SPEED);
      this.direction = drift(this.direction, MAX_DIRECTION_DELTA, MIN_DEGRESS, MAX_DEGREES);
      this.move(this.speed * TICKRATE);
    }
    return {
      name : this.name,
      points : events,
    } 
  }
}

module.exports = Device;