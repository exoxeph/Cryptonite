import sqlite3
from pathlib import Path

import click
from flask import current_app, g


def get_db():
    if "db" not in g:
        database_path = Path(current_app.config["DATABASE_PATH"])
        database_path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(database_path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        g.db = connection
    return g.db


def close_db(e=None):
    connection = g.pop("db", None)
    if connection is not None:
        connection.close()


def init_db():
    schema_path = Path(__file__).with_name("schema.sql")
    schema_sql = schema_path.read_text(encoding="utf-8")
    connection = get_db()
    connection.executescript(schema_sql)
    post_columns = {row["name"] for row in connection.execute("PRAGMA table_info(posts)").fetchall()}
    if "chat_started_at" not in post_columns:
        connection.execute("ALTER TABLE posts ADD COLUMN chat_started_at TEXT")
    user_columns = {row["name"] for row in connection.execute("PRAGMA table_info(users)").fetchall()}
    if "encrypted_bracu_id" not in user_columns:
        connection.execute("ALTER TABLE users ADD COLUMN encrypted_bracu_id BLOB")
    connection.commit()


def execute(query, params=()):
    connection = get_db()
    cursor = connection.execute(query, params)
    connection.commit()
    return cursor


def query_one(query, params=()):
    return get_db().execute(query, params).fetchone()


def query_all(query, params=()):
    return get_db().execute(query, params).fetchall()


@click.command("init-db")
def init_db_command():
    init_db()
    click.echo("Initialized the database.")


def init_app(app):
    app.teardown_appcontext(close_db)
    app.cli.add_command(init_db_command)
