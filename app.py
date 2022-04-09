from auth.utils import (
    create_refresh_token, populate_session,
    remove_token_records, create_access_token)
from auth.auth_logic import validate_login, store_token_in_database
from auth.decorators import token_required
from flask import Flask, session, request, jsonify
import os

app = Flask(__name__)
refresh_token_life = os.getenv('REFRESH_TOKEN_LIFE')


# clean up session data after every request-response cycle
@app.after_request
def clear_session(response):
    if 'token' in session:
        new_access_token = session['token']
        response.set_cookie(
            'auth_token', str(new_access_token),
            max_age=int(refresh_token_life))
    if 'logged_out' in session:
        response.delete_cookie('auth_token')
    if 'refresh_expired' in session:
        response.delete_cookie('auth_token')
    if session:
        for key in list(session.keys()):
            session.pop(key)
        
        session.clear()
        response.delete_cookie('session')
    
    return response


@app.route('/login', methods=['POST'])
def user_login():
    response = {}
    try:
        data = request.form
        user, response = validate_login(data)
        
        if user:
            populate_session(user)
            response = jsonify(response)
            session['refresh_token'] = str(create_refresh_token(session['id']))
            session_data = dict(session)
            token = create_access_token(session_data)
            store_data_tokens = {
                'refresh_token': session['refresh_token'],
                'access_token': str(token),
                'user_id': session['user_id'],
            }
            token_stats = store_token_in_database(store_data_tokens)
            response.set_cookie('auth_token', str(token), max_age=int(refresh_token_life))
            return response
    
    except Exception as e:
        response['error'] = str(e)
        response['success'] = False
        user = None
    
    finally:
        return jsonify(response)


@app.route('/logout')
@token_required
def user_logout():
    response = {}
    try:
        param = session['refresh']
        response = remove_token_records(param)
        for key in list(session.keys()):
            session.pop(key)
        session.clear()
        
        response['logged_out'] = 'Logout successful'
        response['success'] = True
        session['logged_out'] = True
    except Exception as e:
        response['error'] = str(e)
        response['success'] = False
    finally:
        return jsonify(response)
