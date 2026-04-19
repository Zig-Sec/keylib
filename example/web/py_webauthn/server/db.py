import duckdb
from datetime import datetime
import click
from flask import current_app, g

def get_db():
    if 'db' not in g:
        g.con = duckdb.connect(
            current_app.config['DATABASE']
        )

    return g.con


def close_db(e=None):
    db = g.pop('con', None)

    if db is not None:
        db.close()


def init_db():
    con = get_db()

    with current_app.open_resource('schema.sql') as f:
        con.sql(f.read().decode('utf8'))


@click.command('init-db')
def init_db_command():
    """Clear the existing data and create new tables."""
    init_db()
    click.echo('Initialized the database.')

def init_app(app):
    app.teardown_appcontext(close_db)
    app.cli.add_command(init_db_command)
