from urllib import response
from db_instances import db_connection, Refresh_Tokens, User
from datetime import datetime
import bcrypt


def populate_session_from_database(user_id):
    response = {}
    try:
        session = db_connection()
        user = session.query(User).filter(User.USER_ID==user_id).first()
        db_connection.remove()
        return user
    except Exception as e:
        response['success'] = False
        response['message'] = 'Something went wrong'
        response['error'] = str(e)
        return response


def store_token_in_database(data):
    response = {}
    
    try:
        session = db_connection()
        session.add(Refresh_Tokens(
            REFRESH_TOKEN           = data['refresh_token'],
            ACCESS_TOKEN            = data['access_token'],
            USER_ID                 = data['user_id'],
            IS_REFRESH_EXPIRED      = 0,
            IS_ACCESS_EXPIRED       = 0,
            DATE_AT                 = datetime.now()
        ))
        session.flush()
        session.commit()
        response['success'] = True
    
    except Exception as e:
        response['message'] = 'Something went wrong'
        response['error'] = str(e)
        response['success'] = False
    finally:
        db_connection.remove()
    
    return response


def set_new_access_token(expired_access_token, new_token):
    response = {}
    try:
        session = db_connection()
        session.query(Refresh_Tokens)\
            .filter(Refresh_Tokens.ACCESS_TOKEN == expired_access_token)\
            .update({'ACCESS_TOKEN': new_token})
        
        session.flush()
        session.commit()
        response['success'] = True
    except Exception as e:
        response['success'] = False
        response['error'] = str(e)
    finally:
        db_connection.remove()
    
    return response


def remove_token_records(refresh_token):
    response = {}
    try:
        session = db_connection()
        session.query(Refresh_Tokens).filter(
            Refresh_Tokens.REFRESH_TOKEN==refresh_token).delete()
        
        response['success'] = True
        session.commit()
    except Exception as e:
        response['success'] = False
        response['result'] = 'Logout failed'
        response['error'] = str(e)
    finally:
        db_connection.remove()
    
    return response


def validate_refresh_token(refresh_token):
    response = {}
    try:
        session = db_connection()
        is_expired = session.query(Refresh_Tokens.IS_REFRESH_EXPIRED)\
            .filter(Refresh_Tokens.REFRESH_TOKEN == refresh_token).first()
        
        is_expired = is_expired.IS_REFRESH_EXPIRED
        response['success'] = True
        response['is_expired'] = is_expired
        
        if is_expired == 1:
            remove_token_records(refresh_token)
        session.commit()
    except Exception as e:
        response['success'] = False
        response['result'] = 'Logout failed'
        response['error'] = str(e)
    finally:
        db_connection.remove()
    
    return response


def get_user_information(email, password):
    response = {}
    try:
        session = db_connection()
        user = session.query(User)\
            .filter(User.EMAIL==email, User.IS_VERIFIED==1).first()
        
        if not user:
            is_verfied_status = session.query(User.IS_VERIFIED)\
                .filter(User.EMAIL==email).first()
            
            if is_verfied_status == None:
                is_verfied_status_number = 100
            else:
                is_verfied_status_number = 0
            
            if is_verfied_status_number == 0:
                status = 'Email has not verified yet!'
            else:
                status = 'Invalid email or password'
    
    except Exception as e:
        user = None
        response['error'] = str(e)
        response['success'] = False
        response['message'] = 'Something went wrong'
        return user, response
    finally:
        db_connection.remove()
    
    if user:
        hashed_password = user.PASSWORD
        if user.PASSWORD != bcrypt.hashpw(password.encode('UTF_8'), hashed_password.encode('UTF_8')).decode():
            response = {'error': 'Invalid email or password', 'success': False}
            user = None
        else:
            response = {'result': 'Login successful', 'success': True}
    else:
        response = {'error': status, 'success': False}
        user = None
    
    return user, response


def validate_login(data):
    email = data['email']
    password = data['password']
    user, response = get_user_information(email, password)
    return user, response
