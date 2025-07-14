from flask import Blueprint, request, redirect, url_for, render_template, session, jsonify, make_response, flash
from limiter import limiter  # Import the limiter instance
from extensions import socketio
import os
from database.auth_db import upsert_auth
from database.user_db import authenticate_user, User, db_session, find_user_by_username, find_user_by_email, add_user as add_new_user, User
import re
from utils.session import check_session_validity
import secrets
from utils.logging import get_logger

# Initialize logger
logger = get_logger(__name__)

# Access environment variables
LOGIN_RATE_LIMIT_MIN = os.getenv("LOGIN_RATE_LIMIT_MIN", "5 per minute")
LOGIN_RATE_LIMIT_HOUR = os.getenv("LOGIN_RATE_LIMIT_HOUR", "25 per hour")
RESET_RATE_LIMIT = "3 per hour"  # More restrictive rate limit for password reset

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

@auth_bp.errorhandler(429)
def ratelimit_handler(e):
    return jsonify(error="Rate limit exceeded"), 429

@auth_bp.route('/login', methods=['GET', 'POST'])
@limiter.limit(LOGIN_RATE_LIMIT_MIN)
@limiter.limit(LOGIN_RATE_LIMIT_HOUR)
def login():
    if find_user_by_username() is None:
        return redirect(url_for('core_bp.setup'))

    if 'user' in session:
            return redirect(url_for('auth.broker_login'))
    
    if session.get('logged_in'):
        return redirect(url_for('dashboard_bp.dashboard'))

    if request.method == 'GET':
        return render_template('login.html')
    elif request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = authenticate_user(username, password)
        if user:
            session['user'] = username  # Set the username in the session
            session['user_role'] = user.role # Set the user role in the session
            logger.info(f"Login success for user: {username}")
            # Redirect to broker login without marking as fully logged in
            return jsonify({'status': 'success'}), 200
        else:
            return jsonify({'status': 'error', 'message': 'Invalid credentials'}), 401

@auth_bp.route('/broker', methods=['GET', 'POST'])
@limiter.limit(LOGIN_RATE_LIMIT_MIN)
@limiter.limit(LOGIN_RATE_LIMIT_HOUR)
def broker_login():
    if 'user' not in session:
        return redirect(url_for('auth.login'))

    user = find_user_by_username(session['user'])
    if not user:
        return redirect(url_for('auth.logout'))

    if request.method == 'GET':
        # Get broker configuration (already validated at startup)
        BROKER_API_KEY = os.getenv('BROKER_API_KEY')
        BROKER_API_SECRET = os.getenv('BROKER_API_SECRET')
        REDIRECT_URL = os.getenv('REDIRECT_URL')
        broker_name = re.search(r'/([^/]+)/callback$', REDIRECT_URL).group(1)
        
        # Import mask function for credential security
        from utils.auth_utils import mask_api_credential
            
        return render_template('broker.html', 
                             broker_api_key=BROKER_API_KEY,  # Keep original for OAuth redirects
                             broker_api_key_masked=mask_api_credential(BROKER_API_KEY),
                             broker_api_secret=BROKER_API_SECRET,  # Keep original for OAuth redirects  
                             broker_api_secret_masked=mask_api_credential(BROKER_API_SECRET),
                             redirect_url=REDIRECT_URL,
                             broker_name=broker_name)

@auth_bp.route('/reset-password', methods=['GET', 'POST'])
@limiter.limit(RESET_RATE_LIMIT)  # More restrictive rate limit for password reset
def reset_password():
    if request.method == 'GET':
        return render_template('reset_password.html', email_sent=False)
    
    step = request.form.get('step')
    
    if step == 'email':
        email = request.form.get('email')
        user = find_user_by_email(email)
        
        # Always show the same response to prevent user enumeration
        if user:
            session['reset_email'] = email
        
        # Show success message regardless of whether email exists
        return render_template('reset_password.html', 
                             email_sent=True, 
                             totp_verified=False,
                             email=email)
            
    elif step == 'totp':
        email = request.form.get('email')
        totp_code = request.form.get('totp_code')
        user = find_user_by_email(email)
        
        if user and user.verify_totp(totp_code):
            # Generate a secure token for the password reset
            token = secrets.token_urlsafe(32)
            session['reset_token'] = token
            session['reset_email'] = email
            
            return render_template('reset_password.html',
                                 email_sent=True,
                                 totp_verified=True,
                                 email=email,
                                 token=token)
        else:
            flash('Invalid TOTP code. Please try again.', 'error')
            return render_template('reset_password.html',
                                 email_sent=True,
                                 totp_verified=False,
                                 email=email)
            
    elif step == 'password':
        email = request.form.get('email')
        token = request.form.get('token')
        password = request.form.get('password')
        
        # Verify token from session
        if token != session.get('reset_token') or email != session.get('reset_email'):
            flash('Invalid or expired reset token.', 'error')
            return redirect(url_for('auth.reset_password'))
        
        user = find_user_by_email(email)
        if user:
            user.set_password(password)
            db_session.commit()
            
            # Clear reset session data and regenerate session ID for security
            session.pop('reset_token', None)
            session.pop('reset_email', None)
            session.regenerate()
            
            flash('Your password has been reset successfully.', 'success')
            return redirect(url_for('auth.login'))
        else:
            flash('Error resetting password.', 'error')
            return redirect(url_for('auth.reset_password'))
    
    return render_template('reset_password.html', email_sent=False)

@auth_bp.route('/change', methods=['GET', 'POST'])
@check_session_validity
def change_password():
    if 'user' not in session:
        # If the user is not logged in, redirect to login page
        flash('You must be logged in to change your password.', 'warning')
        return redirect(url_for('auth.login'))

    if request.method == 'POST':
        username = session['user']
        old_password = request.form['old_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(old_password):
            if new_password == confirm_password:
                # Here, you should also ensure the new password meets your policy before updating
                user.set_password(new_password)
                db_session.commit()
                # Use flash to notify the user of success
                flash('Your password has been changed successfully.', 'success')
                # Redirect to a page where the user can see this confirmation, or stay on the same page
                return redirect(url_for('auth.change_password'))
            else:
                flash('New password and confirm password do not match.', 'error')
        else:
            flash('Old Password is incorrect.', 'error')
            # Optionally, redirect to the same page to let the user try again
            return redirect(url_for('auth.change_password'))

    return render_template('profile.html', username=session['user'])

@auth_bp.route('/logout', methods=['GET', 'POST'])
def logout():
    if session.get('logged_in'):
        username = session['user']
        
        #writing to database      
        inserted_id = upsert_auth(username, "", "")
        if inserted_id is not None:
            logger.info(f"Database Upserted record with ID: {inserted_id}")
            logger.info(f'Auth Revoked in the Database for user: {username}')
        else:
            logger.error(f"Failed to upsert auth token for user: {username}")
        
        # Remove tokens and user information from session
        session.pop('user', None)  # Remove 'user' from session if exists
        session.pop('broker', None)  # Remove 'user' from session if exists
        session.pop('logged_in', None)

    # Redirect to login page after logout
    return redirect(url_for('auth.login'))

@auth_bp.route('/users', methods=['GET'])
@check_session_validity
def user_management():
    user = find_user_by_username(session['user'])
    if not user or user.role != 'admin':
        return redirect(url_for('dashboard_bp.dashboard'))

    users = User.query.all()
    return render_template('users.html', users=users)

@auth_bp.route('/users/add', methods=['POST'])
@check_session_validity
def add_user():
    user = find_user_by_username(session['user'])
    if not user or user.role != 'admin':
        return redirect(url_for('dashboard_bp.dashboard'))

    username = request.form['username']
    email = request.form['email']
    password = request.form['password']
    role = request.form['role']

    add_new_user(username, email, password, role)

    return redirect(url_for('auth.user_management'))

@auth_bp.route('/users/toggle_access/<int:user_id>', methods=['POST'])
@check_session_validity
def toggle_user_access(user_id):
    user = find_user_by_username(session['user'])
    if not user or user.role != 'admin':
        return redirect(url_for('dashboard_bp.dashboard'))

    user_to_toggle = User.query.get(user_id)
    if user_to_toggle:
        user_to_toggle.is_active = not user_to_toggle.is_active
        db_session.commit()

    return redirect(url_for('auth.user_management'))
