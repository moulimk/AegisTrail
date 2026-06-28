"""Postgres connection helper (psycopg 3).

A connection-per-request context manager. Fine at dev/demo scale; swap for a
pool (psycopg_pool) if throughput ever matters.
"""
import os
from contextlib import contextmanager

import psycopg
from psycopg.rows import dict_row

DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql://aegis:change_me_dev_pw@localhost:5432/aegistrail",
)


@contextmanager
def get_conn():
    with psycopg.connect(DATABASE_URL, row_factory=dict_row) as conn:
        yield conn
