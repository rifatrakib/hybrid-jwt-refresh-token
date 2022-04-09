from db_instances import db_connection, Refresh_Tokens, User


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
