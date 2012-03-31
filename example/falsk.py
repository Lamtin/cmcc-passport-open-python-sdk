#! /usr/bin/python
# -*- coding: utf-8 -*-
import os, sys
sys.path.append(os.path.abspath('..'))

from flask import Flask, session, redirect, url_for, escape, request
from lib.cmcc import ChinaMobile

app = Flask(__name__)

oauth_config = {  \
    'oauth_consumer_key' : 'your oauth consumer key', \
    'oauth_app_secret'   : 'your oauth app secret' \
}

conn = ChinaMobile(oauth_config)

@app.route('/')
def index():
    if 'login' in session:
        return redirect(url_for('auth'))

    try:
        result = conn.get_request_token('http://127.0.0.1:5000/auth')
        session['oauth_token_secret'] = result['oauth_token_secret'][0]
        session['oauth_token'] = result['oauth_token'][0]
        conn.set_token(session['oauth_token'])
        return "<a href='%s'>Login</a>" % (conn.get_authorize_url() ,)
    except:
        return "Error"

@app.route('/auth')
def auth():
    oauth_verifier = request.args.get('oauth_verifier', None)
    if oauth_verifier:
        oauth_verifier = request.args.get('oauth_verifier')
        conn.set_token_secret(session['oauth_token_secret'])
        conn.set_token(session['oauth_token'])
        try:
            result = conn.get_access_token(oauth_verifier)
            session.pop('oauth_token_secret', None)
            session.pop('oauth_token', None)
            session['oauth_access_token_secret'] = result['oauth_token_secret'][0]
            session['oauth_access_token'] = result['oauth_token'][0]
            session['login'] = '1'
            return redirect(url_for('auth'))
        except:
            return "Error"

    if 'login' not in session:
        return redirect(url_for('index'))

    conn.set_token(session['oauth_access_token'])
    conn.set_token_secret(session['oauth_access_token_secret'])

    try:
        user = conn.api_get('user/profile')
        return "Nick Name: %s<br />Email: %s<br />Gender: %s<br /><a href='/logout'>Logout</a>" % (user['nick_name'], user['email'], user['gender'] )
    except:
        return "Error"

@app.route('/logout')
def logout():
    session.pop('oauth_access_token_secret', None)
    session.pop('oauth_access_token', None)
    session.pop('login', None)
    return redirect(url_for('index'))


app.secret_key = 'A0Zr98j/3yX R~XHH!jmN]LWX/,?RT'

if __name__ == '__main__':
    app.run(debug=True)