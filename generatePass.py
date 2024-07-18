from base64 import b64encode
import base64
import hashlib
import logging
import sys
import secrets
import json
import argparse,os
import boto3

def hash_password(password: str, salt: str):

    return b64encode(
        hashlib.pbkdf2_hmac("SHA512", bytearray(password, "UTF-8"), bytearray(salt, "UTF-8"), 5000)
    ).decode("ascii")


def validate_authFile():
    None

def create_auth_json(users, permissionMap):
    return {
        "users": [users],
        "permissions": [permissionMap]
    }



def upload_auth_secret(authFile):


    secretCli = boto3.client('secretsmanager')
   # Upload the JSON data as a secret
    # response = secretCli.create_secret(
    #     Name="eks/tools/sadik/karapace",
    #     SecretString=json.dumps(authFile)
    # )
    # Print the ARN of the created secret
    # print(f"The secret ARN is: {response['ARN']}")

def map_permission_user(username, accessType= "full_admin" ):

    # can extend this to config maps
    permissions ={
    "full_admin" : {
            "operation": "Write",
            "resource": ".*"
        },
    "full_read" : {
            "operation": "Read",
            "resource": ".*"
    } }

    user_permissions = {"username": username}
    user_permissions.update(permissions.get(accessType))
    return user_permissions



def main():
    parser = argparse.ArgumentParser(description='Username password creation.')
    parser.add_argument('--username', type=str, help='User')
    parser.add_argument('--password', type=int, help='password to be hashed')
    args = parser.parse_args()

    auth={}
    # fetch the user names
    username = os.environ.get('KARAPACE_SASL_PLAIN_USERNAME', args.username)
    password = os.environ.get('KARAPACE_SASL_PLAIN_PASSWORD', args.password)

    # Create a random salt
    salt = secrets.token_urlsafe(nbytes=16)

    # prepare a secret json

    if username and password:
        auth["username"] = username
        auth["algorithm"] = "sha512"
        auth["salt"] = salt
        auth["password_hash"] = hash_password( salt, password)




        print(create_auth_json(users=auth, permissionMap=map_permission_user(username)))

        # upload_auth_secret(auth)

    else:
        print("auth file is not created as one of the username/password none")

if __name__ == "__main__":
    sys.exit(main())