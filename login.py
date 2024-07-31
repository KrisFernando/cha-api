import json
import os
import base64
import boto3
import bcrypt

from bson.json_util import dumps  # for converting bson to json
from pymongo.errors import DuplicateKeyError
from jose import JWTError, jws, jwt

# client = boto3.client("secretsmanager")

# Replace with your environment variables
MONGODB_URL = os.environ["MONGODB_URL"]
MONGODB_NAME = os.environ["MONGODB_NAME"]
MONGODB_USR = os.environ["MONGODB_USR"]
MONGODB_PW = os.environ["MONGODB_PW"]
JWT_SECRET_KEY = os.environ["JWT_SECRET_KEY"]
SALT = os.environ["SALT"]
# SECRET_NAME = os.environ["DB_SECRET_NAME"]

""""
def get_secret():
    # Retrieves the MongoDB connection details from AWS Secrets Manager
    get_secret_value_response = client.get_secret_value(SecretId=SECRET_NAME)
    if "SecretString" in get_secret_value_response:
        return json.loads(get_secret_value_response["SecretString"])
    else:
        raise Exception("Secret not found in Secrets Manager")
"""

        
def connect_to_mongodb():
    """Connects to the MongoDB database using connection details from Secrets Manager"""
    # secrets = get_secret()
    mongo_cluster = MONGODB_URL # secrets["host"]
    mongo_db = MONGODB_NAME # secrets["database"]
    mongo_username = MONGODB_USR # secrets["username"]
    mongo_password = MONGODB_PW # base64.b64decode(secrets["password"]).decode("utf-8")

    client = pymongo.MongoClient(
        f"mongodb://{mongo_username}:{mongo_password}@{mongo_cluster}/{mongo_db}"
    )
    return client.get_database(mongo_db)


def lambda_handler(event, context):
    try:
        # Get user data from request body
        data = json.loads(event["body"])
        username = data.get("username")
        password = data.get("password")

        # Basic validation (replace with more robust validation)
        if not username or not password:
            return {
                "statusCode": 400,
                "body": json.dumps({"message": "Missing username or password"}),
            }

        # Connect to MongoDB
        db = connect_to_mongodb()
        users_collection = db["users"]

        # Hash password (using a hashing library like bcrypt)
        hashed_password = hash_password(password)  # Implement your hashing function

        # Check if username already exists
        if users_collection.find_one({"username": username}):
            return {
                "statusCode": 400,
                "body": json.dumps({"message": "Username already exists"}),
            }

        # Create user document
        user = {"username": username, "password": hashed_password}

        # Insert user to database
        try:
            users_collection.insert_one(user)
        except DuplicateKeyError:
            return {
                "statusCode": 400,
                "body": json.dumps({"message": "Username already exists"}),
            }

        # Create access token
        access_token = create_access_token(identity=username)

        return {
            "statusCode": 201,
            "body": json.dumps(
                {"message": "User created successfully", "access_token": access_token}
            ),
        }

    except errors.JWTError as e:
        return {
            "statusCode": 400,
            "body": json.dumps({"message": str(e)}),
        }
    except Exception as e:
        return {
            "statusCode": 500,
            "body": json.dumps({"message": str(e)}),
        }


def hash_password(password):
  # Convert password to bytes (assuming UTF-8 encoding)
  password_bytes = password.encode("utf-8")
  # Hash the password with the salt
  hashed_password = bcrypt.hashpw(password_bytes, SALT)
  return hashed_password


# JWT helper functions (replace with your preferred JWT library implementation)
def create_access_token(identity):
    payload = {"identity": identity}
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm="HS256")


def verify_access_token(token):
    try:
        payload = jws.verify(token, JWT_SECRET_KEY, algorithms=["HS256"])
        return payload["identity"]
    except JWTError:
        raise Exception("Invalid access token")