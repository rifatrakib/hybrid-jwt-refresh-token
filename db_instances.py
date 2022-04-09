from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy.ext.automap import automap_base
from sqlalchemy import create_engine
from sqlalchemy.pool import NullPool
import os

db_uri = os.getenv('DB_URI')
db_engine = create_engine(db_uri, poolclass=NullPool)

base_connection = automap_base()
base_connection.prepare(db_engine, reflect=True)
db_instances = base_connection.classes

User = db_instances.USER
Refresh_Tokens = db_instances.Refresh_Tokens

db_session_factory = sessionmaker(bind=db_engine)
db_connection = scoped_session(db_session_factory)
