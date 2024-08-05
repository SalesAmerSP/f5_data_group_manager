#!/usr/bin/env python3

from cryptography.fernet import Fernet
from config import SECRET_KEY_FILE

def generate_and_save_key(file_path=SECRET_KEY_FILE):
    try:
        key = Fernet.generate_key()
        with open(file_path, 'wb') as key_file:
            key_file.write(key)
        print(f"Key saved to {file_path}")
    except IOError as e:
        print(f"Failed to write key to {file_path}: {e}")

def main():
    generate_and_save_key()

if __name__ == "__main__":
    main()