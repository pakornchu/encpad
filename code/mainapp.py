import base64
import os
import datetime
import urllib.parse
from Crypto.Cipher import AES
from Crypto import Random
from flask import Flask
from flask import render_template, request, redirect, session, jsonify
from flask_talisman import Talisman
import traceback

app = Flask(__name__)
Talisman(app, content_security_policy=[])
app.secret_key = ''
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(minutes=2)

def _genkey():
    key = os.urandom(16)
    return base64.b64encode(key).decode('ascii')

def _decrypt(key, rawdata):
    try:
        keydata = base64.b64decode(key)
        blob = base64.b32decode(rawdata.strip())
        iv = blob[0:AES.block_size]
        enc = AES.new(keydata, AES.MODE_CFB, iv)
        output = enc.decrypt(blob[AES.block_size:])
        return output.decode('utf-8')
    except:
        return 'Error in encryption process'

def _encrypt(key, rawdata):
    try:
        keydata = base64.b64decode(key)
        iv = Random.new().read(AES.block_size)
        enc = AES.new(keydata, AES.MODE_CFB, iv)
        cipher = enc.encrypt(rawdata)
        output = iv + cipher
        return base64.b32encode(output).decode('ascii')
    except:
        return 'Error in encryption process'

@app.route('/')
def showIndex():
    return render_template('index.html')

@app.route('/handler', methods=['POST',])
def handler():
    if 'encaction' in request.form.keys():
        if request.form['encaction'] == 'genkey':
            msg = _genkey()
            return render_template('result.html', msg=msg)
        elif request.form['encaction'] == 'decrypt':
            key = request.form['enckey'].strip()
            data = request.form['ciphertext'].strip()
            msg = _decrypt(key, data)
            encoded = urllib.parse.quote(msg)
            session['msg'] = base64.b64encode(encoded.encode('ascii')).decode('ascii')
            return redirect('/result')
        elif request.form['encaction'] == 'encrypt':
            key = request.form['enckey'].strip()
            data = request.form['ciphertext'].strip()
            msg = _encrypt(key, data)
            return render_template('result.html', msg=msg)

@app.route('/result')
def resultHandler():
    return render_template('resultsecure.html')

@app.route('/getmsg')
def getmsg():
    if 'msg' in session.keys():
        return jsonify({'msg': session['msg']})
    else:
        return jsonify({'msg': base64.b64encode('Message not available'.encode('utf-8')).decode('ascii')})

@app.errorhandler(404)
def error404(e):
    return render_template('404.html')

@app.errorhandler(500)
def error404(e):
    return render_template('500.html')
