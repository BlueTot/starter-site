from typing import Iterator
from mysql.connector.connection import MySQLConnection
import mysql.connector
import os
from contextlib import contextmanager

@contextmanager
def get_db() -> Iterator[MySQLConnection]:
    """
        A context manager for the MySQL database connection
    """
    conn =  mysql.connector.connect(
        host=os.getenv("DB_HOST"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        database=os.getenv("DB_NAME")
    )
    try:
        yield conn # type: ignore[return-value]
    finally:
        conn.close()
