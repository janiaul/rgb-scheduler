from cryptography.fernet import Fernet
import os
from getpass import getpass
import base64

script_dir = os.path.dirname(os.path.abspath(__file__))
key_path = os.path.join(script_dir, "secret.key")


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
            raise ValueError("Password must be at least 8 characters long")
        encrypted_password = fernet.encrypt(password.encode())

        # Encode the encrypted password as a base64 string
        encoded_password = base64.urlsafe_b64encode(encrypted_password).decode()

        return encoded_password

    except FileNotFoundError:
        print("Error: Encryption key not found.")
    except Exception as e:
        print(f"An error occurred: {e}")


def main():
    if not check_key_exists():
        generate_key()
        print("Encryption key generated and saved to 'secret.key'")
    else:
        print("Encryption key already exists")

    encrypted_password = encrypt_password()
    if encrypted_password:
        print("Encrypted password:", encrypted_password)
        print("Please update this value in your config.ini file")


if __name__ == "__main__":
    main()
