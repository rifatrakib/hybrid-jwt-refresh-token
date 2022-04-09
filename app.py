from flask import Flask, session, request
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
