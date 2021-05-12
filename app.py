from flask import Flask, render_template, request, url_for, session, flash, jsonify, redirect, Response
import re
import os
from werkzeug.utils import secure_filename
from flask import send_from_directory
from io import BytesIO
import string
import random
from Algorithms.python import encrypt1, encrypt2, encrypt3, encrypt4, encrypt5, encrypt6
from Algorithms.python import decrypt1, decrypt2, decrypt3, decrypt4, decrypt5, decrypt6
from Algorithms.python import encode1, decode1, encode2, decode2

app = Flask(__name__)

UPLOAD_FOLDER = 'static/images'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


app.secret_key = "prahalad"
secret_key = "sk_test_zfLLQmWiQ0GgfYl1aUOUbnsA00bizNRGYP"
pub_key = "pk_test_GBz9hjRWldkxg9y2Yji4gRs6008l4Q5ry1"


def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
)


@app.errorhandler(404)
def page_not_found(error):
    return 'This page does not exist', 404


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/encryption', methods=['GET'])
def encryption():
    return render_template('encryption.html')


@app.route('/decryption', methods=['GET'])
def decryption():
    return render_template('decryption.html')


@app.route('/term_condition', methods=['GET'])
def term_condition():
    return render_template('term_condition.html')


@app.route('/data_hiding', methods=['GET'])
def data_hiding():
    return render_template('data_hiding.html')


@app.route('/encryption', methods=['POST'])
def getvalue():
    method_type = request.form['method_type']
    encryption_data = request.form['encryption_data']

    if method_type == 'Method 1':
        result = encrypt1(encryption_data)

        return render_template('result.html', result=result,
                               method_type=method_type)

    elif method_type == 'Method 2':
        result = encrypt2(encryption_data)

        return render_template('result.html', result=result,
                               method_type=method_type)

    elif method_type == 'Method 3':
        result = encrypt3(encryption_data)

        return render_template('result.html', result=result,
                               method_type=method_type)

    elif method_type == 'Method 4':
        result = encrypt4(encryption_data)

        return render_template('result.html', result=result,
                               method_type=method_type)

    elif method_type == 'Method 5':
        result = encrypt5(encryption_data)
        tt = 1

        return render_template('result.html', result=result[0],
                               result1=result[1], method_type=method_type, tt=tt)

    elif method_type == 'method6':
        encryption_key = request.form['encryption_key']
        result = encrypt6(encryption_data, encryption_key)

        return render_template('result.html', result=result,
                               method_type=method_type)

    else:
        result = 'Select A Right Method'
        return render_template('result.html', result=result)


@app.route('/decryption', methods=['POST'])
def getvalues():
    method_type = request.form['method_type']
    decryption_data = request.form['decryption_data']

    if method_type == 'Method 1':
        result = decrypt1(decryption_data)

        return render_template('result.html', result=result,
                               method_type=method_type)

    elif method_type == 'Method 2':
        result = decrypt2(decryption_data)

        return render_template('result.html', result=result,
                               method_type=method_type)

    elif method_type == 'Method 3':
        result = decrypt3(decryption_data)

        return render_template('result.html', result=result,
                               method_type=method_type)

    elif method_type == 'Method 4':
        result = decrypt4(decryption_data)

        return render_template('result.html', result=result,
                               method_type=method_type)

    elif method_type == 'Method 5':
        result = decrypt5(decryption_data)
        tt = 1

        return render_template('result.html', result=result[0],
                               result1=result[1], method_type=method_type, tt=tt)

    elif method_type == 'method6':
        decryption_key = request.form['decryption_key']
        result = decrypt6(decryption_data, decryption_key)

        return render_template('result.html', result=result,
                               method_type=method_type)

    else:
        result = 'Select A Right Method'
        return render_template('result.html', result=result)


@app.route('/data_hiding', methods=['POST'])
def upload_file():

    method_type = request.form['method_type']
    passwd = request.form['passwd']

    if 'file' not in request.files:
        flash('No file part')
        return redirect(request.url)
    file = request.files['file']

    if file.filename == '':
        flash('No selected file')
        return redirect(request.url)

    if file:
        filename = secure_filename(file.filename)
        input_filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

    if method_type == 'Method 1':
        hiding_data = request.form['hiding_data']
        new_img_name = request.form['new_img_name']

        path = encode1(input_filepath, hiding_data,
                       new_img_name, app.config['UPLOAD_FOLDER'])
        session['path'] = path
        tt = 1

        return render_template('stegno.html', path=path, tt=tt, method_type=method_type)

    elif method_type == 'Method 2':

        path = decode1(input_filepath)
        session['path'] = path

        return render_template('stegno.html', path=path, method_type=method_type)

    elif method_type == 'Method 3':
        hiding_data = request.form['hiding_data']
        new_img_name = request.form['new_img_name']

        path = encode2(input_filepath, hiding_data, new_img_name,
                       app.config['UPLOAD_FOLDER'], passwd)
        session['path'] = path
        tt = 1

        return render_template('stegno.html', path=path, tt=tt, method_type=method_type)

    elif method_type == 'Method 4':

        path = decode2(input_filepath, passwd)
        session['path'] = path

        return render_template('stegno.html', path=path, method_type=method_type)

    elif method_type == 'Method 5':
        hiding_data = request.form['hiding_data']
        new_img_name = request.form['new_img_name']

        path = encode2(input_filepath, hiding_data, new_img_name,
                       app.config['UPLOAD_FOLDER'], passwd)
        session['path'] = path
        tt = 1

        return render_template('stegno.html', path=path, tt=tt, method_type=method_type)

    elif method_type == 'Method 6':
        path = decode2(input_filepath, passwd)
        session['path'] = path

        return render_template('stegno.html', path=path, method_type=method_type)

    else:

        result = 'Select A Right Method'
        return render_template('result.html', result=result)


if __name__ == "__main__":
    app.run(debug=True)
