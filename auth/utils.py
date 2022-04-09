from auth.auth_logic import (
    validate_refresh_token, remove_token_records,
    populate_session_from_database, set_new_access_token)
from flask import session, redirect, url_for
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
import json
import jwt
import os

access_token_life = os.getenv('ACCESS_TOKEN_LIFE')
refresh_token_key = os.getenv('REFRESH_TOKEN_SECRET_KEY')
payload_key = os.getenv('PAYLOAD_SECRET_KEY')
access_token_key = os.getenv('JWT_SECRET_KEY')
refresh_token_life = os.getenv('REFRESH_TOKEN_LIFE')


def get_data_for_session(data):
    user_id = data['user_id']
    user_info = populate_session_from_database(user_id)
    return user_info


def populate_session(user):
    for key in list(session.keys()):
        session.pop(key)
    session.clear()
    
    # extend this list to include more information in the token payload as necessary
    # and make the corresponding columns available in the database
    payload_items = ['user_id', 'email', 'first_name', 'last_name', 'logged_in']
    for key in payload_items:
        session[key] = str(getattr(user, key.upper()))


def create_refresh_token(user_id):
    expiry = datetime.utcnow() + timedelta(seconds=refresh_token_life)
    refresh_token = jwt.encode({
        'data': user_id,
        'exp': expiry
    }, refresh_token_key, algorithm='HS256')
    
    return refresh_token


def create_access_token(data):
    if data['refresh_token'][:2] == "b'" and data['refresh_token'][-1] == "'":
        # this occurs in Windows OS for any version due to MS compilers
        data['refresh_token'] = data['refresh_token'][2:-1]
    
    payload = str(json.dumps(data))
    access_token_encrypter = Fernet(payload_key)
    payload_data = access_token_encrypter.encrypt(payload.encode())
    
    token = jwt.encode({
        'data': payload_data.decode(),
        'exp': datetime.utcnow() + timedelta(seconds=int(access_token_life))
    }, access_token_key, algorithm='HS256')
    
    return token


def decrypt_payload(token, token_key, payload_key, options=None):
    encrypter = Fernet(payload_key)
    try:
        original = jwt.decode(token, token_key, algorithms=['HS256'], options=options)
        decoded_data = encrypter.decrypt(str.encode(original['data']))
        response = json.loads(decoded_data.decode())
    except jwt.exceptions.ExpiredSignatureError:
        response = {'error': 'Signature expired', 'expired': True}
    except jwt.InvalidTokenError:
        response = {'error': 'Invalid token. Please log in again.', 'invalid': True}
    except Exception as e:
        response = {'error': 'Something went wrong', 'exception': str(e)}
    finally:
        return response


def extract_refresh_token(refresh_token):
    if refresh_token[:2] == "b'" and refresh_token[-1] == "'":
        # this occurs in Windows OS for any version due to MS compilers
        refresh_token = refresh_token[2:-1]
    
    try:
        original = jwt.decode(refresh_token, refresh_token_key, algorithms=['HS256'])
        expiry = original['exp']
        check_from_db = validate_refresh_token(str(refresh_token))
        
        if check_from_db['is_expired'] == 0:
            return {'success': True, 'expiry': expiry}
        else:
            session['refresh'] = refresh_token
            session['refresh_expired'] = True
            return check_from_db['is_expired']
    
    except jwt.exceptions.ExpiredSignatureError as e:
        print('refresh token expired')
        session['refresh'] = refresh_token
        session['refresh_expired'] = True
        remove_token_records(str(refresh_token))
        return redirect(url_for('logout'))
    
    except jwt.InvalidTokenError as e:
        print('token invalid')
        session['refresh'] = refresh_token
        session['refresh_expired'] = True
        return redirect(url_for('logout'))
    
    except Exception as e:
        print(str(e))
        session['refresh'] = refresh_token
        session['refresh_expired'] = True
        return redirect(url_for('user_logout'))


def extract_access_payload(token):
    refresh_response = {}
    is_refresh_expired = False
    if token[:2] == "b'" and token[-1] == "'":
        # this occurs in Windows OS for any version due to MS compilers
        token = token[2:-1]
    
    decoded_data_dict = decrypt_payload(token, access_token_key, payload_key)
    
    if 'error' in decoded_data_dict:
        if 'expired' in decoded_data_dict:
            decoded_data_dict = decrypt_payload(token, access_token_key, payload_key, {'verify_exp': False})
            expired_access_token = str(token)
            refresh_response = extract_refresh_token(decoded_data_dict['refresh_token'])
            
            if isinstance(refresh_response, dict):
                if 'success' in refresh_response:
                    token = create_access_token(decoded_data_dict)
                    # Update the access token in database
                    set_new_access_token(expired_access_token, str(token))
            else:
                is_refresh_expired = True
        
        elif 'invalid' in decoded_data_dict:
            return {'success': False, 'status': decoded_data_dict['error']}
        else:
            return {'success': False, 'status': decoded_data_dict['exception']}
        
    user_data = get_data_for_session(decoded_data_dict)
    populate_session(user_data)
    session['refresh'] = decoded_data_dict['refresh_token']
    
    if refresh_response:
        session['token'] = str(token)
        
    if is_refresh_expired:
        session['refresh_expired'] = True
        
    return decoded_data_dict
