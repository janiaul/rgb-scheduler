"""
Generate and encrypt a password for the RGB Scheduler web interface.
Usage: (from project root)
    python -m scripts.generate_password
"""

from cryptography.fernet import Fernet
import os
import sys
from getpass import getpass
import base64

try:
    from rgb_scheduler.path_utils import get_data_path
except ImportError:
    print(
        "Error: Cannot import utils. Run this script from the project root with: python -m scripts.generate_password"
    )
    sys.exit(1)

key_path = get_data_path("secret.key")


def check_key_exists():
    return os.path.exists(key_path)


def generate_key():
    key = Fernet.generate_key()
    with open(key_path, "wb") as key_file:
        key_file.write(key)


def encrypt_password():
    try:
        with open(key_path, "rb") as key_file:
            key = key_file.read()
        fernet = Fernet(key)
        password = getpass("Enter the password to encrypt: ")
        if len(password) < 8:
            print("Error: Password must be at least 8 characters long.")
            return None
        encrypted_password = fernet.encrypt(password.encode())
        # Encode the encrypted password as a base64 string
        encoded_password = base64.urlsafe_b64encode(encrypted_password).decode()
        return encoded_password
    except FileNotFoundError:
        print(f"Error: Encryption key not found at {key_path}.")
    except Exception as e:
        print(f"An error occurred: {e}")


def main():
    print("==== RGB Scheduler Password Encryption Tool ====\n")
    if not check_key_exists():
        generate_key()
        print(f"Encryption key generated and saved to '{key_path}'.")
    else:
        print(f"Encryption key already exists at '{key_path}'.")
    encrypted_password = encrypt_password()
    if encrypted_password:
        print("\nEncrypted password:\n", encrypted_password)
        print(
            "\nUpdate this value in the [web] section of your config.ini file as the password."
        )
    else:
        print("\nNo encrypted password generated.")


if __name__ == "__main__":
    main()
