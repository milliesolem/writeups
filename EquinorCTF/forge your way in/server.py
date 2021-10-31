from flask import Flask, render_template, url_for, abort, request, redirect, make_response
import time
import sys
import os
from binascii import hexlify, unhexlify
from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.Cipher.AES import block_size
from Crypto.Util.Padding import pad, unpad
from waitress import serve
app = Flask(__name__)
admin_password = open(os.path.join("secrets", "adminpassword.txt"), "r").read()
key = b64decode(open(os.path.join("secrets", "key.txt"), "r").read())[:block_size]

BAD_REQUEST = 400
UNAUTHORIZED = 401
FORBIDDEN = 403
INTERNAL_SERVER_ERROR = 500

def parseKeyValue(s):
    pairs = s.split("&")
    _dict = {}
    for pair in pairs:
        key, value = pair.split("=")
        _dict[key] = value
    return _dict

def encrypt_auth_cookie(auth):
    return AES.new(key=key, mode=AES.MODE_ECB).encrypt(pad(auth.encode("ASCII"), block_size))

def decrypt_auth_cookie(auth):
    return parseKeyValue(unpad(AES.new(key=key, mode=AES.MODE_ECB).decrypt(unhexlify(auth)), block_size).decode("ASCII"))

def validate_auth(auth):
    try:
        decrypted_auth = decrypt_auth_cookie(auth)
        if "username" in decrypted_auth and "user_is_admin" in decrypted_auth and "current_time" in decrypted_auth:
            return decrypted_auth.get("username")
    except:
        abort(INTERNAL_SERVER_ERROR)

def validate_admin(auth):
    try:
        decrypted_auth = decrypt_auth_cookie(auth)
        valid_auth = validate_auth(auth)
        return valid_auth and int(decrypted_auth.get("user_is_admin", False))
    except:
        abort(INTERNAL_SERVER_ERROR)

def get_auth_cookie(username, admin=False):
    if "&" in username or "=" in username:
        abort(BAD_REQUEST)
    user_is_admin = 1 if admin else 0
    return hexlify(encrypt_auth_cookie(f"username={username}&current_time={str(int(time.time()))}&user_is_admin={user_is_admin}"))

@app.route('/')
def index():
    auth = request.cookies.get('auth')
    if auth:
        username = validate_auth(auth)
        if username:
            return render_template('index.html', username=username)
        abort(BAD_REQUEST)
    return redirect(url_for('login'))

# Route for handling the login page logic
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username and password:
            response = make_response(redirect(url_for('index')))
            if username == 'admin':
                if password == admin_password:
                    auth_cookie = get_auth_cookie(username=username, admin=True)
                else:
                    return render_template('login.html', error='Invalid Credentials. Please try again.')
            else:
                auth_cookie = get_auth_cookie(username=username)
            response.set_cookie('auth', auth_cookie) 
            return response
        else:
            abort(BAD_REQUEST)
    return render_template('login.html', error=error)

# Route for handling the login page logic
@app.route('/logout')
def logout():
    response = make_response(redirect(url_for('index')))
    response.set_cookie('auth', '', expires=0)
    return response
    
@app.route('/flag', methods=['GET'])
def flag():
    auth = request.cookies.get('auth')
    if auth and validate_auth(auth):
        if validate_admin(auth):
            return open(os.path.join("secrets", "flag.txt"), "r").read()
        else:
            return render_template('forbidden_flag.html'), FORBIDDEN
    abort(UNAUTHORIZED)


if __name__ == '__main__':
    if sys.platform.lower() == "win32": 
        os.system('color')
    serve(app, host="0.0.0.0", port=1234)
    app.run(port=1234)