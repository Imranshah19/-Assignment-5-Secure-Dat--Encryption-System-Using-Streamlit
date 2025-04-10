import hashlib
import base64
from cryptography.fernet import Fernet

# Generate a Fernet encryption key using the passkey
def generate_fernet_key(passkey):
    # First, hash the passkey using SHA-256 to get a 32-byte key
    hash_key = hashlib.sha256(passkey.encode()).digest()
    # Convert the hashed key into a URL-safe base64 format (required by Fernet)
    return Fernet(base64.urlsafe_b64encode(hash_key))

# Hash the passkey (for secure storage and verification)
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Encrypt plain text using the passkey
def encrypt_text(text, passkey):
    key = generate_fernet_key(passkey)         # Generate Fernet key from passkey
    return key.encrypt(text.encode()).decode() # Encrypt text and convert to string

# Decrypt encrypted text using the correct passkey
def decrypt_text(encrypted_text, passkey):
    key = generate_fernet_key(passkey)            # Generate Fernet key again
    return key.decrypt(encrypted_text.encode()).decode()  # Decrypt and return text

