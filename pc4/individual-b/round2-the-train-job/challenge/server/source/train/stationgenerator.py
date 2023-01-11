
# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

from trainnetwork import Station, TrainNetwork
import json


STATIONS = [
    ("Architect Colony", 1),
    ("Fable Terminal", 1),
    ("Spectrum Colony", 1),
    ("Scout Station", 1),
    ("Data Terminal", 1),
    ("Eternity Station", 1),
    ("Iris Base", 1),
    ("Prism Colony", 1),
    ("Proto Colony", 1),
    ("Aegis Station", 1),
    ("Angel Station", 1),
    ("Prophecy Colony", 1),
    ("Legacy Base", 1),
    ("Victoria Station", 3),
    ("Azura Colony", 1),
    ("Parable Station", 1),
    ("Miracle Colony", 1),
]


def create_network():
    network = TrainNetwork()

    for name, security_level in STATIONS:
        network.new_station(Station(name, security_level))

    network.connect_stations(STATIONS[0][0], STATIONS[1][0], 1)
    network.connect_stations(STATIONS[1][0], STATIONS[2][0], 1)
    network.connect_stations(STATIONS[2][0], STATIONS[3][0], 1)

    network.connect_stations(STATIONS[3][0], STATIONS[4][0], 1)
    network.connect_stations(STATIONS[3][0], STATIONS[5][0], 1)
    network.connect_stations(STATIONS[3][0], STATIONS[6][0], 1)

    network.connect_stations(STATIONS[4][0], STATIONS[5][0], 1)

    network.connect_stations(STATIONS[5][0], STATIONS[7][0], 1)

    network.connect_stations(STATIONS[6][0], STATIONS[7][0], 1)
    network.connect_stations(STATIONS[6][0], STATIONS[8][0], 1)
    network.connect_stations(STATIONS[6][0], STATIONS[9][0], 1)

    network.connect_stations(STATIONS[8][0], STATIONS[9][0], 1)
    network.connect_stations(STATIONS[8][0], STATIONS[11][0], 1)

    network.connect_stations(STATIONS[9][0], STATIONS[10][0], 1)

    network.connect_stations(STATIONS[10][0], STATIONS[11][0], 1)
    network.connect_stations(STATIONS[10][0], STATIONS[12][0], 1)

    network.connect_stations(STATIONS[11][0], STATIONS[13][0], 1)

    network.connect_stations(STATIONS[12][0], STATIONS[13][0], 1)

    network.connect_stations(STATIONS[13][0], STATIONS[14][0], 1)
    network.connect_stations(STATIONS[13][0], STATIONS[15][0], 1)

    network.connect_stations(STATIONS[14][0], STATIONS[16][0], 1)

    network.connect_stations(STATIONS[15][0], STATIONS[16][0], 1)

    with open("network.json", "w") as f:
        json.dump(network.to_dict(), f)

