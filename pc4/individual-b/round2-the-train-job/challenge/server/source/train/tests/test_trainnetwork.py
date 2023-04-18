
# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

from itertools import product
import json
from sys import maxsize

import pytest

from ..trainnetwork import Station, TrainNetwork, AlreadyAtDestinationError


@pytest.fixture
def two_station_network():
    station_a = Station("A", 1)
    station_b = Station("B", 1)

    network = TrainNetwork()
    network.new_station(station_a)
    network.new_station(station_b)

    network.connect_stations(station_a, station_b, 1)

    return [station_a, station_b], network


@pytest.fixture
def four_station_network():
    stations = []
    for name, security in zip("ABCD", (1, 2, 1, 1)):
        station = Station(name, security)
        stations.append(station)

    network = TrainNetwork()
    [network.new_station(station) for station in stations]

    station_a, station_b, station_c, station_d = stations

    network.connect_stations(station_a, station_b, 1)
    network.connect_stations(station_b, station_d, 1)
    network.connect_stations(station_a, station_c, 2)
    network.connect_stations(station_c, station_d, 1)

    return stations, network


def test_station():
    name = "A"
    station_a = Station(name, 1)
    assert station_a.name == name
    assert station_a.security_level == 1


def test_connect_stations():
    station_a = Station("A", 1)
    station_b = Station("B", 1)

    station_a.connect(station_b, 1)

    assert station_b in station_a.connections.keys()
    assert station_a not in station_b.connections.keys()

    station_b.connect(station_a, 1)

    assert station_a in station_b.connections.keys()


def test_network_two_stations(two_station_network):
    (station_a, station_b), network = two_station_network
    assert station_a in station_b.connections.keys()
    assert station_b in station_a.connections.keys()


def test_network_find_path_two_stations(two_station_network):
    (station_a, station_b), network = two_station_network

    path = network.find_path(station_a, station_b, maxsize)

    assert path == [station_a, station_b]


def test_network_find_path_no_security_limit(four_station_network):
    (station_a, station_b, station_c, station_d), network = four_station_network

    path = network.find_path(station_a, station_d, maxsize)

    assert path == [station_a, station_b, station_d]


def test_network_find_path_security_limit(four_station_network):
    (station_a, station_b, station_c, station_d), network = four_station_network

    path = network.find_path(station_a, station_d, 1)

    assert path == [station_a, station_c, station_d]


def test_station_to_dict(two_station_network):
    (station_a, station_b), _ = two_station_network

    assert station_a.to_dict() == {
        "name": "A",
        "security_level": 1,
        "connections": {"B": 1},
    }
    assert station_b.to_dict() == {
        "name": "B",
        "security_level": 1,
        "connections": {"A": 1},
    }


def test_network_to_dict(two_station_network):
    _, network = two_station_network

    assert network.to_dict() == {
        "A": {"name": "A", "security_level": 1, "connections": {"B": 1}},
        "B": {"name": "B", "security_level": 1, "connections": {"A": 1}},
    }


def test_network_from_dict(two_station_network):
    _, network = two_station_network

    assert network.equals(
        TrainNetwork.from_dict(
            {
                "A": {"name": "A", "security_level": 1, "connections": {"B": 1}},
                "B": {"name": "B", "security_level": 1, "connections": {"A": 1}},
            }
        )
    )


def test_all_pairs_in_network_json():
    with open("network.json") as f:
        data = json.load(f)

    network = TrainNetwork.from_dict(data)
    all_pairs = product(network._stations_by_name, repeat=2)

    for pair in all_pairs:
        try:
            network.find_path(*pair, maxsize)
        except AlreadyAtDestinationError:
            a, b = pair
            if a != b:
                raise AssertionError(
                    f"Got AlreadyAtDestinationError with different stations in pair: {(a, b)}"
                )

