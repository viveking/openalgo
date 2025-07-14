from flask import Blueprint, render_template, session, redirect, url_for, g, jsonify, request
from database.auth_db import get_auth_token
from database.user_db import find_user_by_username
from database.broker_db import get_user_brokers, get_user_broker, set_active_broker
from importlib import import_module
from utils.session import check_session_validity
import multiprocessing
import sys
from utils.logging import get_logger

logger = get_logger(__name__)

def dynamic_import(broker):
    try:
        module_path = f'broker.{broker}.api.funds'
        module = import_module(module_path)
        get_margin_data = getattr(module, 'get_margin_data')
        return get_margin_data
    except ImportError as e:
        logger.error(f"Error importing module: {e}")
        return None

dashboard_bp = Blueprint('dashboard_bp', __name__, url_prefix='/')
scalper_process = None

@dashboard_bp.route('/dashboard')
@check_session_validity
def dashboard():
    user = find_user_by_username(session['user'])
    if not user:
        return redirect(url_for('auth.logout'))

    brokers = get_user_brokers(user.id)
    active_broker_name = session.get('broker')
    active_broker = None
    margin_data = None

    if active_broker_name:
        active_broker = get_user_broker(user.id, active_broker_name)

    if active_broker:
        get_margin_data_func = dynamic_import(active_broker.broker_name)
        if get_margin_data_func:
            margin_data = get_margin_data_func(active_broker.broker_token)

    return render_template('dashboard.html', margin_data=margin_data, brokers=brokers, active_broker=active_broker)

@dashboard_bp.route('/switch_broker/<broker_name>')
@check_session_validity
def switch_broker(broker_name):
    user = find_user_by_username(session['user'])
    if not user:
        return redirect(url_for('auth.logout'))

    broker = get_user_broker(user.id, broker_name)
    if broker:
        set_active_broker(user.id, broker_name)
        session['broker'] = broker_name
        session['AUTH_TOKEN'] = broker.broker_token
        if broker.broker_feed_token:
            session['FEED_TOKEN'] = broker.broker_feed_token

    return redirect(url_for('dashboard_bp.dashboard'))
