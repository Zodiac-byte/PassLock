import sqlite3
import os
import hashlib
from cryptography.fernet import Fernet
import base64
import pyotp
import qrcode
from PIL import Image


conn = sqlite3.connect("example.db")
cursor = conn.cursor()

passwords = '''
CREATE TABLE IF NOT EXISTS accounts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    service_name TEXT NOT NULL,
    username TEXT NOT NULL,
    password TEXT NOT NULL
);
'''

master_pass = '''
CREATE TABLE IF NOT EXISTS master_password (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    totp TEXT NOT NULL
);
'''

cursor.execute(passwords)
cursor.execute(master_pass)

insert_query = '''
INSERT INTO accounts (service_name, username, password)
VALUES (?, ?, ?)
'''


def cls_con():
    print("\033[H\033[J", end="")


def setup_mfa():
    totp_secret = pyotp.random_base32()
    totp = pyotp.TOTP(totp_secret)
    totp_uri = totp.provisioning_uri(name='PassLock', issuer_name='SparshCo.')
    qr = qrcode.make(totp_uri)
    qr_image = qr.convert("RGB")
    qr_image.show()
    return totp_secret


def verify_totp(user_totp_input, totp_secret):
    totp = pyotp.TOTP(totp_secret)
    return totp.verify(user_totp_input)


def set_master_password():
    salt = os.urandom(16).hex()

    master_password = input("Please choose a master password: ")
    totp_secret = setup_mfa()

    password_hash = hashlib.sha256((master_password + salt).encode()).hexdigest()

    cursor.execute('''
    INSERT INTO master_password (password_hash, salt, totp)
    VALUES (?, ?, ?)
    ''', (password_hash, salt, totp_secret))

    conn.commit()


def derive_key_from_password(mpassword, salt):
    key = hashlib.pbkdf2_hmac('sha256', mpassword.encode(), salt.encode(), 100000)
    return Fernet(base64.urlsafe_b64encode(key[:32]))


def verify_master_password():
    cursor.execute('SELECT password_hash, salt, totp FROM master_password')
    result = cursor.fetchone()

    if result is None:
        print("Master password is not set.")
        return False

    stored_hash, salt, totp = result

    master_password = input("Please enter your master password: ")
    entered_hash = hashlib.sha256((master_password + salt).encode()).hexdigest()

    if entered_hash == stored_hash:
        print("Open Google Authenticator for the next step")
        user_totp_input = input("Enter the TOTP code (30 seconds): ")
        if verify_totp(user_totp_input, totp):
            print("Access granted")
            cls_con()
            return True
    else:
        print("Access denied")
        return False


def get_fernet():
    master_password = input("Please enter your master password again: ")
    cursor.execute('SELECT salt FROM master_password')
    salt = cursor.fetchone()[0]
    ernet = derive_key_from_password(master_password, salt)
    return ernet


cursor.execute('SELECT * FROM master_password')
if cursor.fetchone() is None:
    set_master_password()
else:
    print("Master password already set.")


def encrypt(plain_pass, fernet):
    return fernet.encrypt(plain_pass.encode()).decode()


def decrypt(encrypted_pass, fernet):
    return fernet.decrypt(encrypted_pass.encode()).decode()


if verify_master_password():
    fernet = get_fernet()
    while True:
        cls_con()
        c = input("Type 1 for creating a new password or Type 2 for reading previous passwords (Type 3 to exit): ")
        if c == "1":
            website = input("Enter the Website this password would be used for: ")
            user = input("Enter the username: ")
            password = input("Enter the password: ")
            repass = input("Re-enter the password: ")

            if password == repass:
                if verify_master_password():
                    epass = encrypt(password, fernet=fernet)
                    euser = encrypt(user, fernet)
                    values = (website, euser, epass)
                    cursor.execute(insert_query, values)
                    conn.commit()
                    cls_con()
            else:
                cls_con()
                print("Please enter your details again")

        elif c == "2":
            cls_con()
            select_all = '''SELECT * FROM accounts'''
            cursor.execute(select_all)
            rows = cursor.fetchall()
            for row in rows:
                print(row)
            q = input("\nWhich website do you want the details to?").lower()
            for row in rows:
                if q == row[1]:
                    if verify_master_password():
                        print(f"Website: {row[1]}")
                        print(f"Username: {decrypt(row[2], fernet)}")
                        print(f"Password: {decrypt(row[3], fernet)}")

        elif c == "3":
            break

conn.close()
