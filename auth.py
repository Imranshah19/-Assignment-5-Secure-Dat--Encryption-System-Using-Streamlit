import hashlib
import os
import hmac
import base64
import json
from pathlib import Path

# Constants
SALT_SIZE = 16
KEY_LENGTH = 32
ITERATIONS = 100000

def hash_password(password, salt=None):
    """
    Generate a secure hash of the password using PBKDF2.
    Returns the hash and salt used.
    """
    if salt is None:
        salt = os.urandom(SALT_SIZE)
    
    password_hash = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode(),
        salt,
        ITERATIONS,
        KEY_LENGTH
    )
    
    return password_hash, salt

def verify_password(password, stored_hash, salt):
    """
    Verify a password against a stored hash.
    """
    password_hash, _ = hash_password(password, salt)
    return hmac.compare_digest(password_hash, stored_hash)

class UserAuthManager:
    def __init__(self, storage_file='users.json'):
        self.storage_file = storage_file
        self.users = self._load_users()
    
    def _load_users(self):
        """Load user data from storage file"""
        if not Path(self.storage_file).exists():
            return {}
        
        try:
            with open(self.storage_file, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            return {}
    
    def _save_users(self):
        """Save user data to storage file"""
        with open(self.storage_file, 'w') as f:
            json.dump(self.users, f)
    
    def register_user(self, username, password):
        """
        Register a new user.
        Returns True on success, False if user already exists.
        """
        if username in self.users:
            return False
        
        password_hash, salt = hash_password(password)
        
        self.users[username] = {
            'hash': base64.b64encode(password_hash).decode('utf-8'),
            'salt': base64.b64encode(salt).decode('utf-8')
        }
        
        self._save_users()
        return True
    
    def authenticate_user(self, username, password):
        """
        Authenticate a user with username and password.
        Returns True if authentication is successful, False otherwise.
        """
        if username not in self.users:
            return False
        
        user_data = self.users[username]
        stored_hash = base64.b64decode(user_data['hash'])
        salt = base64.b64decode(user_data['salt'])
        
        return verify_password(password, stored_hash, salt)
    
    def change_password(self, username, current_password, new_password):
        """
        Change a user's password.
        Returns True on success, False if authentication fails.
        """
        if not self.authenticate_user(username, current_password):
            return False
        
        password_hash, salt = hash_password(new_password)
        
        self.users[username] = {
            'hash': base64.b64encode(password_hash).decode('utf-8'),
            'salt': base64.b64encode(salt).decode('utf-8')
        }
        
        self._save_users()
        return True
    
    def delete_user(self, username, password):
        """
        Delete a user account.
        Returns True on success, False if authentication fails.
        """
        if not self.authenticate_user(username, password):
            return False
        
        del self.users[username]
        self._save_users()
        return True 