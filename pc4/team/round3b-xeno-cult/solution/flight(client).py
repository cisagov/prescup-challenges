#!/usr/bin/python3
# https://github.com/realpython/materials/tree/master/python-sockets-tutorial

import time
import random
import sys
import socket
import os

HOST = "203.0.113.16"  # The server's hostname or IP address
PORT = 1337  # The port used by the server

num_of_ships = 500
num_of_probes = 20000

# Set Space Grid's Min/Max X and Min/Max Y.

min_x = 0
max_x = 4095
min_y = 0
max_y = 4095

# valid_x contains 1-4094 to keep numbers from increasing past Min X - Max X.
valid_x = list(range(min_x+1, max_x))

# valid_y contains 1-4094 to keep numbers from increasing past Min Y - Max Y.
valid_y = list(range(min_y+1, max_y))

# Set xy coordinates of home base
base = {'x': 3519, 'y': 2231}

outputpath = './probelocations.txt' 


# Delete old output file, if exists
if os.path.exists(outputpath):
    os.remove(outputpath)

class Ship(object):
    def __init__(self, shipname, x, y, direction):
        self.shipname = shipname
        self.x = x
        self.y = y
        self.direction = direction


shipnames = []

for i in range(num_of_ships):
    shipname = "ship_"+str(i)
    shipnames.append(shipname)


# Set list of random X coords for all ships

ship_xs = []
for i in range(num_of_ships):
    ship_xs.append(random.randint(0,max_x))

# Set list of random Y coords for all ships
ship_ys = []
for i in range(num_of_ships):
    ship_ys.append(random.randint(0,max_y))

ship_directions = []
eight_directions = ['n', 'ne', 'e', 'se', 's', 'sw', 'w', 'nw']

# Set list of random directions for all ships
for i in range(num_of_ships):
    ship_directions.append(random.choice(eight_directions))

# List comprehension to have all Ship class instances in one ships list
ships = [Ship(shipname, ship_xs, ship_ys, directions) for shipname, ship_xs, ship_ys, directions in zip(shipnames, ship_xs, ship_ys, ship_directions)]

class Probe(object):
    def __init__(self, probename, x, y, direction):
        self.probename = probename
        self.x = x
        self.y = y
        self.direction = direction

# Set appropriate starting coordinates based on ship direction

for ship in ships:
    if ship.direction == 'n':
        offset = random.randint(10, max_x)
        ship.x = base['x']
        ship.y = base['y'] - offset
    if ship.direction == 's':
        offset = random.randint(10, max_x)
        ship.x = base['x']
        ship.y = base['y'] + offset
    if ship.direction == 'e':
        offset = random.randint(10, max_x)
        ship.x = base['x'] - offset
        ship.y = base['y']
    if ship.direction == 'w':
        offset = random.randint(10, max_x)
        ship.x = base['x'] + offset
        ship.y = base['y']
    if ship.direction == 'ne':
        offset = random.randint(10, max_x)
        ship.x = base['x'] - offset
        ship.y = base['y'] - offset
    if ship.direction == 'nw':
        offset = random.randint(10, max_x)
        ship.x = base['x'] + offset
        ship.y = base['y'] - offset
    if ship.direction == 'se':
        offset = random.randint(10, max_x)
        ship.x = base['x'] - offset
        ship.y = base['y'] + offset
    if ship.direction == 'sw':
        offset = random.randint(10, max_x)
        ship.x = base['x'] + offset
        ship.y = base['y'] + offset

# Set names of probes
probenames = []
for i in range(num_of_probes):
    probename = "probe_"+str(i)
    probenames.append(probename)

# Randomize probe names.
random.shuffle(probenames)

# Set list of random X coords for all probes
probe_xs = []
for i in range(num_of_probes):
    probe_xs.append(random.randint(0,max_x))

# Set list of random Y coords for all probes
probe_ys = []
for i in range(num_of_probes):
    probe_ys.append(random.randint(0,max_y))

# Set list of random directions for all probes
probe_directions = []
eight_directions = ['n', 'ne', 'e', 'se', 's', 'sw', 'w', 'nw']
for i in range(num_of_probes):
    probe_directions.append(random.choice(eight_directions))

# List comprehension to have all Probe class instances in one probes list
probes = [Probe(probename, probe_xs, probe_ys, probe_directions) for probename, probe_xs, probe_ys, probe_directions in zip(probenames, probe_xs, probe_ys, probe_directions)]

def printship():
    #Convert decimals to HEX with 3 characters (needed for up to 4095). Leading zeroes are added, if needed.
    ship_x_hex = f"{ship.x:x}".upper().zfill(3)
    ship_y_hex = f"{ship.y:x}".upper().zfill(3)
    shipstatus = ship.shipname+" "+ship_x_hex+" "+ship_y_hex+" "+ship.direction
    print(shipstatus)
    return shipstatus

def printprobe():
    #Convert decimals to HEX with 3 characters (needed for up to 4095). Leading zeroes are added, if needed.
    probe_x_hex = f"{probe.x:x}".upper().zfill(3)
    probe_y_hex = f"{probe.y:x}".upper().zfill(3)
    probestatus = probe.probename+" "+probe_x_hex+" "+probe_y_hex+" "+probe.direction
    print(probestatus)
    return probestatus

def writeprobe():
    probe_x_hex = f"{probe.x:x}".upper().zfill(3)
    probe_y_hex = f"{probe.y:x}".upper().zfill(3)
    probestatus = probe.probename+" "+probe_x_hex+" "+probe_y_hex+" "+probe.direction
    with open(outputpath, 'a', encoding='utf-8') as f:
        epoch_time = str(time.time())
        f.write(epoch_time+":"+probestatus+"\n")

def moveship():
    global ship
    for ship in ships:
# Verify ship is notat base and still in grid (disregard direction), continue moving.
# Delete ship from lists to simulate it leaving grid.
        if ship.x not in valid_x or ship.y not in valid_y:
            ships.remove(ship)
        elif (ship.x != base['x'] or ship.y != base['y']) and ship.x in valid_x and ship.y in valid_y:
            if ship.direction == 'n':
                ship.y = ship.y + 1
                printship()
            if ship.direction == 's':
                ship.y = ship.y - 1
                printship()
            if ship.direction == 'e':
                ship.x = ship.x + 1
                printship()
            if ship.direction == 'w':
                ship.x = ship.x - 1
                printship()
            if ship.direction == 'ne':
                ship.y = ship.y + 1
                ship.x = ship.x + 1
                printship()
            if ship.direction == 'nw':
                ship.y = ship.y + 1
                ship.x = ship.x - 1
                printship()
            if ship.direction == 'se':
                ship.y = ship.y - 1
                ship.x = ship.x + 1
                printship()
            if ship.direction == 'sw':
                ship.y = ship.y - 1
                ship.x = ship.x - 1
                printship()
            if ship.x == base['x'] and ship.y == base['y']:
                printship()
                print("^Landed at Base^")

def moveprobe():
    global probe
    for probe in probes:
        time.sleep(0.005)
# Verify probe is still in grid (disregard direction), continue moving.
# Delete probe if out of grid to simulate probe leaving monitoring area.
        if probe.x not in valid_x or probe.y not in valid_y:
            probes.remove(probe)
        elif probe.x in valid_x and probe.y in valid_y:
            if probe.direction == 'n':
                probe.y = probe.y + 1
                printprobe()
                writeprobe()
            if probe.direction == 's':
                probe.y = probe.y - 1
                printprobe()
                writeprobe()
            if probe.direction == 'e':
                probe.x = probe.x + 1
                printprobe()
                writeprobe()
            if probe.direction == 'w':
                probe.x = probe.x - 1
                printprobe()
                writeprobe()
            if probe.direction == 'ne':
                probe.y = probe.y + 1
                probe.x = probe.x + 1
                printprobe()
                writeprobe()
            if probe.direction == 'nw':
                probe.y = probe.y + 1
                probe.x = probe.x - 1
                printprobe()
                writeprobe()
            if probe.direction == 'se':
                probe.y = probe.y - 1
                probe.x = probe.x + 1
                printprobe()
                writeprobe()
            if probe.direction == 'sw':
                probe.y = probe.y - 1
                probe.x = probe.x - 1
                printprobe()
                writeprobe()
            if probe.x == base['x'] and probe.y == base['y']:
                print("↓PROBE FOUND BASE! Signal Needs Jammed!↓")
                epoch_time = str(time.time())
                print(epoch_time)
                printprobe()
                print(base)
                print("↑PROBE FOUND BASE! Signal Needs Jammed↑")
                sys.exit()
            sighting = False
            for ship in ships:
                if probe.x == ship.x and probe.y == ship.y:
                    sighting = True
                    print("↓PROBE FOUND SHIP! Signal Needs Jammed!↓")
                    epoch_time = str(time.time())
                    print(epoch_time)
                    printprobe()
                    ship_x_hex = f"{ship.x:x}".upper().zfill(3)
                    ship_y_hex = f"{ship.y:x}".upper().zfill(3)
                    shipstatus = ship.shipname+" "+ship_x_hex+" "+ship_y_hex+" "+ship.direction
                    print(shipstatus)
                    print("↑PROBE FOUND SHIP! Signal Needs Jammed!↑")
            if sighting == False:
                senddata()
            else:
                # do not senddata() if sighting is False. Set sighting to False for next iteration.
                sighting = False
def senddata():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        message = str(printprobe())
        bytesmessage = message.encode()
        s.sendall(bytesmessage)
        data = s.recv(1024)

while True:
    moveship()
    moveprobe()
