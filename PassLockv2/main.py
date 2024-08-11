import os
import hashlib
import base64
from flask import Flask, request, render_template, redirect
from cryptography.fernet import Fernet
import sqlite3

app = Flask(__name__)


def get_db_connection():
    conn = sqlite3.connect('example.db')
    conn.row_factory = sqlite3.Row
    return conn


def create_tables():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Create accounts table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS accounts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        service_name TEXT NOT NULL,
        username TEXT NOT NULL,
        password TEXT NOT NULL
    );
    ''')

    # Create master_password table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS master_password (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        password_hash TEXT NOT NULL,
        salt TEXT NOT NULL
    );
    ''')

    conn.commit()


# Call this function to create tables
create_tables()


def derive_key_from_password(mpassword, salt):
    key = hashlib.pbkdf2_hmac('sha256', mpassword.encode(), salt.encode(), 100000)
    return Fernet(base64.urlsafe_b64encode(key[:32]))



@app.route('/set_master', methods=['GET', 'POST'])
def set_master():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Check if the master password is already set
    cursor.execute('SELECT * FROM master_password')
    if cursor.fetchone():
        conn.close()
        # Redirect to login with a message if master password is already set
        return redirect('/login?error=Password has already been set')

    if request.method == 'POST':
        salt = os.urandom(16).hex()
        master_password = request.form['master_password']

        password_hash = hashlib.sha256((master_password + salt).encode()).hexdigest()

        cursor.execute('''
        INSERT INTO master_password (password_hash, salt)
        VALUES (?, ?)
        ''', (password_hash, salt))

        conn.commit()
        conn.close()

        return redirect('/login')

    conn.close()
    return render_template('set_master.html')



@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        master_password = request.form['master_password']

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT password_hash, salt FROM master_password')
        result = cursor.fetchone()
        conn.close()

        if result:
            stored_hash, salt = result
            entered_hash = hashlib.sha256((master_password + salt).encode()).hexdigest()

            if entered_hash == stored_hash:
                return redirect('/dashboard')
            else:
                return redirect('/login?error=Incorrect master password')
        else:
            return redirect('/login?error=Master password not set')

    error = request.args.get('error')
    return render_template('login.html', error=error)


@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')


@app.route('/add_password', methods=['GET', 'POST'])
def add_password():
    if request.method == 'POST':
        service_name = request.form['service_name']
        username = request.form['username']
        password = request.form['password']
        repass = request.form['repassword']
        master_password = request.form['master_password']

        if password != repass:
            return render_template('add_password.html', error='Passwords do not match')

        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('SELECT password_hash, salt FROM master_password')
            result = cursor.fetchone()
            conn.close()

            if not result:
                return render_template('add_password.html', error='Master password not set.')

            stored_hash, salt = result
            entered_hash = hashlib.sha256((master_password + salt).encode()).hexdigest()

            if entered_hash != stored_hash:
                return render_template('add_password.html', error='Incorrect master password.')

            fernet = derive_key_from_password(master_password, salt)
            encrypted_password = fernet.encrypt(password.encode()).decode()
            encrypted_username = fernet.encrypt(username.encode()).decode()

            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('''
            INSERT INTO accounts (service_name, username, password)
            VALUES (?, ?, ?)
            ''', (service_name, encrypted_username, encrypted_password))

            conn.commit()
            conn.close()
            return redirect('/dashboard')
        except Exception as e:
            return render_template('add_password.html', error='An error occurred while adding the password.')

    return render_template('add_password.html')


@app.route('/view_passwords', methods=['GET', 'POST'])
def view_passwords():
    if request.method == 'POST':
        master_password = request.form['master_password']
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT salt FROM master_password')
        result = cursor.fetchone()
        conn.close()

        if result:
            stored_salt = result[0]
            fernet = derive_key_from_password(master_password, stored_salt)

            try:
                conn = get_db_connection()
                cursor = conn.cursor()
                cursor.execute('SELECT * FROM accounts')
                rows = cursor.fetchall()
                conn.close()

                decrypted_passwords = []
                for row in rows:
                    decrypted_passwords.append({
                        'service_name': row['service_name'],
                        'username': fernet.decrypt(row['username'].encode()).decode(),
                        'password': fernet.decrypt(row['password'].encode()).decode()
                    })

                print(decrypted_passwords)  # Debugging statement
                return render_template('view_passwords.html', passwords=decrypted_passwords)
            except Exception as e:
                # Handle decryption error
                return f"Error decrypting passwords: {e}"
        else:
            return redirect('/login?error=Master password not set')

    return render_template('view_passwords.html')




if __name__ == '__main__':
    app.run(debug=True)
