from cryptography.fernet import Fernet

def load_key():
    return open('secret.key', 'rb').read()

def encrypt_password(password):
    key = load_key()
    f = Fernet(key)
    encrypted_password = f.encrypt(password.encode())
    return encrypted_password.decode()

def decrypt_password(encrypted_password):
    try:
        key = load_key()
        f = Fernet(key)
        decrypted_password = f.decrypt(encrypted_password.encode())
        return decrypted_password.decode()
    except cryptography.fernet.InvalidToken:
        print("Invalid Token: Decryption failed")
        return None
