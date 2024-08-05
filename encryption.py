#!/usr/bin/env python3

import cryptography
from cryptography.fernet import Fernet

def load_key():
    """
    Load the secret key from the 'secret.key' file.
    Returns:
        bytes: The secret key.
    Raises:
        FileNotFoundError: If the 'secret.key' file does not exist.
        IOError: If there is an error reading the 'secret.key' file.
    """
    try:
        with open('secret.key', 'rb') as key_file:
            return key_file.read()
    except FileNotFoundError:
        print("Error: 'secret.key' file not found.")
        raise
    except IOError as e:
        print(f"Error reading 'secret.key' file: {e}")
        raise

def encrypt_password(password):
    """
    Encrypt a password using the secret key.
    Args:
        password (str): The password to encrypt.
    Returns:
        str: The encrypted password.
    Raises:
        ValueError: If the password is empty.
    """
    if not password:
        raise ValueError("Password cannot be empty.")
    
    key = load_key()
    f = Fernet(key)
    encrypted_password = f.encrypt(password.encode())
    return encrypted_password.decode()

def decrypt_password(encrypted_password):
    """
    Decrypt an encrypted password using the secret key.
    Args:
        encrypted_password (str): The encrypted password to decrypt.
    Returns:
        str: The decrypted password, or None if decryption fails.
    Raises:
        ValueError: If the encrypted password is empty.
    """
    if not encrypted_password:
        raise ValueError("Encrypted password cannot be empty.")
    
    try:
        key = load_key()
        f = Fernet(key)
        decrypted_password = f.decrypt(encrypted_password.encode())
        return decrypted_password.decode()
    except cryptography.fernet.InvalidToken:
        print("Invalid Token: Decryption failed.")
        return None
    except Exception as e:
        print(f"An error occurred during decryption: {e}")
        return None