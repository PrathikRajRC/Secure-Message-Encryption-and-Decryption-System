import hashlib
import os
import json

AUTH_FILE = "auth_data.json"

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def authenticate_user(username, password):
    users = load_users()
    stored_password_hash = users.get(username)
    return stored_password_hash == hash_password(password)

def create_user(username, password):
    users = load_users()
    password_hash = hash_password(password)
    users[username] = password_hash
    save_users(users)

def load_users():
    if os.path.exists(AUTH_FILE):
        with open(AUTH_FILE, 'r') as file:
            return json.load(file)
    return {}

def save_users(users):
    with open(AUTH_FILE, 'w') as file:
        json.dump(users, file)
