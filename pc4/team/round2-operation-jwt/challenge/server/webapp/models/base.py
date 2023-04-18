
# Copyright 2023 Carnegie Mellon University.
# Released under a MIT (SEI)-style license, please see LICENSE.md in the project 
# root or contact permission@sei.cmu.edu for full terms.

from peewee import SqliteDatabase, Model


_db_connection = SqliteDatabase(None, pragmas=[("foreign_keys", "on")])


class PeeweeBase(Model):
    class Meta:
        database = _db_connection

