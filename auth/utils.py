from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from secrets import get_var
import json
import jwt

access_token_time = get_var('ACCESS_TOKEN_TIME')


def create_refresh_token(user_id):
    token_key = get_var('REFRESH_TOKEN_SECRET_KEY')
    expiry = datetime.utcnow() + timedelta(seconds=15778800)
    refresh_token = jwt.encode({
        'data': user_id,
        'exp': expiry
    }, token_key, algorithm='HS256')
    return refresh_token


def create_access_token(data):
    if data['refresh_token'][:2] == "b'" and data['refresh_token'][-1] == "'":
        data['refresh_token'] = data['refresh_token'][2:-1]
    payload = str(json.dumps(data))
    payload_key = get_var("PAYLOAD_SECRET_KEY")
    token_key = get_var("JWT_SECRET_KEY")
    access_token_encrypter = Fernet(payload_key)
    payload_data = access_token_encrypter.encrypt(payload.encode())
    token = jwt.encode({
        'data': payload_data.decode(),
        'exp': datetime.utcnow() + timedelta(seconds=int(access_token_time))
    }, token_key, algorithm='HS256')
    return token
