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

    # Create master_password table with a UNIQUE constraint
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS master_password (
        id INTEGER PRIMARY KEY,
        password_hash TEXT NOT NULL,
        salt TEXT NOT NULL,
        UNIQUE(id)
    );
    ''')

    conn.commit()


    conn.commit()
    conn.close()

# Call this function to create tables
create_tables()

def derive_key_from_password(mpassword, salt):
    key = hashlib.pbkdf2_hmac('sha256', mpassword.encode(), salt.encode(), 100000)
    return Fernet(base64.urlsafe_b64encode(key[:32]))

@app.route('/set_master', methods=['GET', 'POST'])
def set_master():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT COUNT(*) FROM master_password')
    count = cursor.fetchone()[0]
    conn.close()

    if count > 0:
        return 'Master password is already set. You cannot set it again.', 403

    if request.method == 'POST':
        salt = os.urandom(16).hex()
        master_password = request.form['master_password']

        password_hash = hashlib.sha256((master_password + salt).encode()).hexdigest()

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
        INSERT INTO master_password (id, password_hash, salt)
        VALUES (1, ?, ?)
        ''', (password_hash, salt))

        conn.commit()

        return redirect('/login')

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

        return 'Invalid credentials'

    return render_template('login.html')

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

        if password == repass:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('SELECT salt FROM master_password')
            salt = cursor.fetchone()[0]
            conn.close()

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
        else:
            return 'Passwords do not match'

    return render_template('add_password.html')


@app.route('/view_passwords')
def view_passwords():
    master_password = request.args.get('master_password')

    if not master_password:
        return 'Master password is required', 400

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT salt FROM master_password')
    salt_row = cursor.fetchone()
    conn.close()

    if not salt_row:
        return 'Master password has not been set', 400

    salt = salt_row[0]

    if not salt:
        return 'Salt value is missing', 400

    fernet = derive_key_from_password(master_password, salt)

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM accounts')
    rows = cursor.fetchall()
    conn.close()

    decrypted_passwords = []
    for row in rows:
        if row['username'] and row['password']:
            try:
                decrypted_passwords.append({
                    'service_name': row['service_name'],
                    'username': fernet.decrypt(row['username'].encode()).decode(),
                    'password': fernet.decrypt(row['password'].encode()).decode()
                })
            except Exception as e:
                return f'Error decrypting data: {e}', 500
        else:
            return 'Database entries contain None values', 400

    return render_template('view_passwords.html', passwords=decrypted_passwords)


if __name__ == '__main__':
    app.run(debug=True)
