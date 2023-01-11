
# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

from sys import maxsize

SecurityLevel = int


class StationDoesNotExistError(Exception):
    pass


class SourceDoesNotExistError(StationDoesNotExistError):
    pass


class DestinationDoesNotExistError(StationDoesNotExistError):
    pass


class AlreadyAtDestinationError(Exception):
    pass


class Station:
    def __init__(self, name: str, security_level: SecurityLevel):
        self.name = name
        self.security_level = security_level
        self.connections = {}

    def connect(self, other: "Station", distance: int):
        self.connections[other] = distance

    # using __eq__ makes it unhashable
    def equals(self, other: "Station"):
        self_dict = {k.name: distance for k, distance in self.connections.items()}
        other_dict = {k.name: distance for k, distance in other.connections.items()}
        return (
            self.name == other.name
            and self.security_level == other.security_level
            and self_dict == other_dict
        )

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "security_level": self.security_level,
            "connections": {
                station.name: distance for station, distance in self.connections.items()
            },
        }

    @classmethod
    def from_dict(cls, json_data: dict) -> "Station":
        return cls(json_data["name"], json_data["security_level"])


class TrainNetwork:
    def __init__(self):
        self._stations_by_name = {}

    def new_station(self, station: Station):
        self._stations_by_name[station.name] = station

    def _lookup_station(self, station: str | Station):
        if isinstance(station, Station):
            station = station.name
        try:
            return self._stations_by_name[station]
        except KeyError:
            raise StationDoesNotExistError(station)

    def connect_stations(
        self, station_a: str | Station, station_b: str | Station, distance: int
    ):
        station_a = self._lookup_station(station_a)
        station_b = self._lookup_station(station_b)

        station_a.connect(station_b, distance)
        station_b.connect(station_a, distance)

    def find_path(
        self,
        source_station: str | Station,
        destination_station: str | Station,
        security_level_limit: SecurityLevel,
    ) -> list[Station] | None:
        if source_station == destination_station:
            raise AlreadyAtDestinationError

        try:
            source_station = self._lookup_station(source_station)
        except StationDoesNotExistError as e:
            raise SourceDoesNotExistError(str(e)) from None

        try:
            destination_station = self._lookup_station(destination_station)
        except StationDoesNotExistError as e:
            raise DestinationDoesNotExistError(str(e)) from None

        shortest_paths = {}
        route = {}
        unvisited = set()
        for station in self._stations_by_name.values():
            if station.security_level > security_level_limit:
                continue
            shortest_paths[station] = maxsize
            route[station] = None
            unvisited.add(station)
        shortest_paths[source_station] = 0

        while unvisited:
            visit_next = None
            for station in unvisited:
                if visit_next is None:
                    visit_next = station
                elif shortest_paths[station] < shortest_paths[visit_next]:
                    visit_next = station
            unvisited.remove(visit_next)

            for neighbor, distance in visit_next.connections.items():
                if neighbor not in unvisited:
                    continue

                candidate_path_distance = shortest_paths[visit_next] + distance
                if candidate_path_distance < shortest_paths[neighbor]:
                    shortest_paths[neighbor] = candidate_path_distance
                    route[neighbor] = visit_next

        previous = route[destination_station]
        path = [destination_station, previous]
        while previous := route[previous]:
            path.append(previous)

        if path[-1] != source_station:
            return None

        return path[::-1]

    # using __eq__ makes it unhashable
    def equals(self, other: "TrainNetwork") -> bool:
        self_keys, other_keys = set(self._stations_by_name.keys()), set(
            other._stations_by_name.keys()
        )
        if self_keys != other_keys:
            return False
        for key in self_keys:
            if not self._stations_by_name[key].equals(other._stations_by_name[key]):
                return False
        return True

    def to_dict(self) -> dict:
        return {
            name: station.to_dict() for name, station in self._stations_by_name.items()
        }

    @classmethod
    def from_dict(cls, json_data: dict) -> "TrainNetwork":
        network = cls()
        # Make station nodes first.
        for _, station_dict in json_data.items():
            station = Station.from_dict(station_dict)
            network.new_station(station)
        # Then connect them.
        for name, station_dict in json_data.items():
            for other_name, distance in station_dict["connections"].items():
                network.connect_stations(name, other_name, distance)
        return network

