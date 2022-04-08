from botocore.exceptions import ClientError, NoCredentialsError
import base64
import boto3
import os


def get_secret():
    secret_name = "add your aws secret manager uri"
    region_name = "add your aws server region"
    
    try:
        session = boto3.session.Session()
        client = session.client(service_name='secretsmanager', region_name=region_name)
        get_secret_value_response = client.get_secret_value(SecretId=secret_name)
    except ClientError as e:
        print('--> error:\n\t', e)
        return {}
    except NoCredentialsError as e:
        print('--> error:\n\t', e)
        print('No credentials')
        return {}
    else:
        if 'SecretString' in get_secret_value_response:
            secret = get_secret_value_response['SecretString']
            return eval(secret)
        else:
            decoded_binary_secret = base64.b64decode(get_secret_value_response['SecretBinary'])
            print('--> Decoded binary secret:', decoded_binary_secret)
    
    return {}


def get_var(var_name):
    temp_var = secret_dict.get(var_name, os.getenv(var_name))
    if (temp_var == None):
        temp_var = 'Missing'
    
    return temp_var


secret_dict = get_secret()
