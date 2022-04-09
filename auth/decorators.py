from auth.utils import extract_access_token_payload
from flask import request, jsonify
from functools import wraps


def token_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        token = request.cookies.get('auth_token', None)
        
        if token:
            extracted_payload = extract_access_token_payload(token)
            if 'error' in extracted_payload:
                return jsonify(extracted_payload)
        else:
            return jsonify({'error': 'Not logged in'})
        
        # Here data can be loaded for further extension of authentication
        # by chaining more decorators which will feed on the data loaded
        return func(*args, **kwargs)
    
    return wrapper
