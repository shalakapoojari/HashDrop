from base64 import urlsafe_b64encode
import hashlib
from cryptography.fernet import Fernet

def encrypt_file(file_path, filename, uploaded_at):
    """
    Encrypts a file using a generated encryption key.
    Returns the encrypted data and encryption key.
    """
    try:
        with open(file_path, "rb") as f:
            file_data = f.read()

        # Generate encryption key
        raw_key = hashlib.sha256(f"{filename}{uploaded_at.timestamp()}".encode()).digest()
        encryption_key = urlsafe_b64encode(raw_key[:32])  # 32-byte key

        # Encrypt file
        fernet = Fernet(encryption_key)
        encrypted_data = fernet.encrypt(file_data)

        return encrypted_data, encryption_key.decode()
    except Exception as e:
        print(f"Error encrypting file: {e}")
        return None, None



def decrypt_file(encrypted_data, key):
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_data)
