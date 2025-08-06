# database/broker_db.py

import os
from sqlalchemy import create_engine, Column, Integer, String, Boolean, ForeignKey, Text
from sqlalchemy.orm import scoped_session, sessionmaker, relationship
from sqlalchemy.ext.declarative import declarative_base
from utils.logging import get_logger

logger = get_logger(__name__)

DATABASE_URL = os.getenv('DATABASE_URL')

engine = create_engine(
    DATABASE_URL,
    pool_size=50,
    max_overflow=100,
    pool_timeout=10
)

db_session = scoped_session(sessionmaker(autocommit=False, autoflush=False, bind=engine))
Base = declarative_base()
Base.query = db_session.query_property()

class UserBroker(Base):
    __tablename__ = 'user_brokers'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    broker_name = Column(String(50), nullable=False)
    broker_token = Column(Text, nullable=False)
    broker_feed_token = Column(Text, nullable=True)
    is_active = Column(Boolean, default=True)

def init_db():
    """Initialize the broker database"""
    logger.info("Initializing Broker DB")
    Base.metadata.create_all(bind=engine)

def add_broker_to_user(user_id, broker_name, broker_token, broker_feed_token=None):
    """Add a new broker to a user"""
    new_broker = UserBroker(
        user_id=user_id,
        broker_name=broker_name,
        broker_token=broker_token,
        broker_feed_token=broker_feed_token
    )
    db_session.add(new_broker)
    db_session.commit()
    return new_broker

def get_user_brokers(user_id):
    """Get all brokers for a user"""
    return UserBroker.query.filter_by(user_id=user_id, is_active=True).all()

def get_user_broker(user_id, broker_name):
    """Get a specific broker for a user"""
    return UserBroker.query.filter_by(user_id=user_id, broker_name=broker_name, is_active=True).first()

def set_active_broker(user_id, broker_name):
    """Set the active broker for a user"""
    brokers = get_user_brokers(user_id)
    for broker in brokers:
        if broker.broker_name == broker_name:
            broker.is_active = True
        else:
            broker.is_active = False
    db_session.commit()
