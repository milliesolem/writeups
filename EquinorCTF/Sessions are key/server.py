import base64
from flask import Flask, render_template, url_for, abort, request, redirect, make_response
import sys
import os
from waitress import serve
import hashlib
from base64 import b64decode, b64encode
import json
import user_management
from models import User

app = Flask(__name__)
flag = open("flag.txt", "r").read()
key = hashlib.sha224(flag.encode("ascii")).hexdigest()

BAD_REQUEST = 400
UNAUTHORIZED = 401
INTERNAL_SERVER_ERROR = 500

ADMIN_PERMISSIONS = "1"
USER_PERMISSIONS = "0"


def bytes_to_sign(cookie):
    return key.encode() + b"".join([x.encode()+b64decode(y) for x,y in sorted(cookie.items())])

def sign_session_cookie(cookie):
    return hashlib.md5(bytes_to_sign(cookie)).hexdigest()

def validate_signature(cookie, signature):
    if not signature:
        abort(INTERNAL_SERVER_ERROR)
    string_to_sign = bytes_to_sign(cookie)
    if hashlib.md5(string_to_sign).hexdigest() != signature:
        abort(UNAUTHORIZED)
    return True

def get_session_cookie():
    try:
        return json.loads(base64.b64decode(request.cookies.get("session")))
    except:
        return {}

def create_session_cookie(user_level, username):
    cookie = {"user_level": b64encode(user_level.encode()).decode(), "username": b64encode(username.encode()).decode()}
    signature = sign_session_cookie(cookie)
    cookie["signature"] = signature
    return base64.b64encode(json.dumps(cookie).encode())

def validate_session(required_permissions):
    session_cookie = get_session_cookie()
    if "signature" not in session_cookie:
        return False
    signature = session_cookie.pop("signature")
    if validate_signature(session_cookie, signature):
        session_userlevel = b64decode(session_cookie["user_level"]).decode()
        return session_userlevel >= required_permissions
    else:
        return False

def get_logged_in_user():
    return b64decode(get_session_cookie().get("username", "")).decode()

def login_user(username, user_level, resp):
    resp.set_cookie('session', create_session_cookie(user_level=user_level, username=username))

@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        username, permissions  = user_management.validate_login(username=username, password=password)
        if username and permissions:
                resp = redirect(url_for('index'))
                login_user(username, permissions, resp)
                return resp
        else:
            msg = 'Unable to log you in'
            resp = redirect(url_for('login', msg=msg))
            return resp
    else:
        return make_response(render_template('login.html', msg=request.args.get('msg')))

@app.route('/register', methods=['POST', 'GET'])
def register():
    return user_management.register()

@app.route('/logout', methods=['GET'])
def logout():
    resp = redirect(url_for('login'))
    resp.set_cookie('session')
    return resp

@app.route('/demo', methods=['GET'])
def demo():
    resp = redirect(url_for('index'))
    login_user("demo", USER_PERMISSIONS, resp)
    return resp

@app.route('/admin', methods=['GET'])
def admin():
    if validate_session(ADMIN_PERMISSIONS):
        return make_response(render_template('admin.html', flag=flag))
    abort(UNAUTHORIZED)

@app.route('/', methods=['GET'])
def index():
    if validate_session(USER_PERMISSIONS):
        return make_response(render_template('index.html', username=get_logged_in_user()))
    else:
        return redirect(url_for('login'))

if __name__ == '__main__':
    if sys.platform.lower() == "win32": 
        os.system('color')
    serve(app, host="0.0.0.0", port=1234)