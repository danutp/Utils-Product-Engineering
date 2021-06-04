#!/usr/bin/python
# -*- coding: utf-8 -*-

"""SQLite module utils."""


import sqlite3
from os import linesep


class SqliteUtils(object):
    """SQLite related tasks."""

    def __init__(self, sqlite_file=None, table_name=None, use_transaction=False):
        """Initialize the SQLite instance.
        :param sqlite_file: Path to the SQLite file [str]
        :param table_name: Name of the SQLite table [str]
        :param use_transaction: Use transactions [bool]
        """
        self.__sqlite_file = sqlite_file
        self.__table_name = table_name
        self.__use_transaction = use_transaction

    @property
    def sqlite_file(self):
        """Get the SQLite file."""
        return self.__sqlite_file

    @property
    def table_name(self):
        """Get the table name as in SQLite db."""
        return self.__table_name

    @property
    def use_transaction(self):
        """Use transactions flag."""
        return self.__use_transaction

    def connect(self):
        """Connect to DB.
        :return: Connection, on success
                 None, on failure
        """
        try:
            connection = sqlite3.connect(self.sqlite_file, detect_types=sqlite3.PARSE_DECLTYPES)
        except Exception as error:
            print(
                "{line_sep}"
                "Error when trying to connect to database: '{db}'"
                "{line_sep}\t{err}{line_sep}".format(line_sep=linesep, db=self.sqlite_file, err=error)
            )
            return False

        return connection

    def fetch_query_db(self, sql_query=None):
        """Fetch all entries from DB.
        :param sql_query: Query to use [str]
        :return ROWS, on success
                False, on failure
                None, if no input provided
        """
        if not sql_query:
            return

        try:
            connection = self.connect()
            with connection:
                cursor = connection.cursor()
                cursor.execute(sql_query)
                rows = cursor.fetchall()
        except Exception as err:
            print(
                "{line_sep}"
                "Error when trying to query table: '{table}'"
                "{line_sep}\t{err}\n".format(line_sep=linesep, table=self.table_name, err=err)
            )
            return False

        return rows

    def run_query_db(self, sql_query=None):
        """Run SQL query on DB. Can use transactions.
        :param sql_query: Values to insert [str]
        :return True, on success
                False, on failure
                None, if no input provided
        """
        if not sql_query:
            return

        try:
            connection = self.connect()
            with connection:
                cursor = connection.cursor()

                if self.use_transaction:
                    # Add this because the Context Manager does not do anything on __enter__
                    # On error => Context Manager will roll-back the transaction on __exit__
                    cursor.execute("BEGIN TRANSACTION;")

                cursor.execute(sql_query)
                connection.commit()
        except Exception as err:
            print(
                "{line_sep}Error when trying to run SQL query for table: '{table}'"
                "{line_sep}SQL query"
                "{line_sep}{query}{line_sep}"
                "{line_sep}\t{err}\n".format(line_sep=linesep, table=self.table_name, query=sql_query, err=err)
            )
            return False

        return True
