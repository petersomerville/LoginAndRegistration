import re, bcrypt
from flask import Flask, session, request, redirect, render_template, flash, url_for
from flask_wtf import CSRFProtect
from db.data_layer import get_user_by_email, get_user_by_id, create_user

app = Flask(__name__)
app.secret_key = 'blah'

csrf = CSRFProtect(app)

EMAIL_REGEX = re.compile(r'^([a-zA-Z0-9_\-\.]+)@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.)|(([a-zA-Z0-9\-]+\.)+))([a-zA-Z]{2,4}|[0-9]{1,3})(\]?)$')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/authenticate')
def authenticate():
    return render_template('authenticate.html')

@app.route('/register', methods = ['POST'])
def register():
    email = request.form['html_email']
    username = request.form['html_username']
    password = request.form['html_password']
    confirm = request.form['html_confirm']

    is_valid = True

    if not EMAIL_REGEX.match(email):
        flash("invalid email address")
        is_valid = False

    if is_empty('email', request.form):
        is_valid = False
    
    if is_empty('username', request.form):
        is_valid = False
    
    if is_empty('password', request.form):
        is_valid = False

    if password != confirm:
        flash('passwords do not match')
        is_valid = False

    if is_valid == False:
        return redirect(url_for('authenticate'))

    try:
        encoded_utf8 = password.encode('UTF-8')
        encrypted = bcrypt.hashpw(encoded_utf8, bcrypt.gensalt())
        user = create_user(email, username, encrypted)
        session['user_id'] = user.id
        session['username'] = user.name
    except:
        flash('user already exists')
        return redirect(url_for('authenticate'))

    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/login', methods = ['POST'])
def login():
    
    try:
        user = get_user_by_email(request.form['html_email'])
        encoded_utf8 = request.form['html_password'].encode('UTF-8')    
        if bcrypt.checkpw(encoded_utf8, user.password):
            session['user_id'] = user.id
            session['username'] = user.name
            return redirect(url_for('index'))
    except:
        raise
        pass    

    flash('Invalid login')
    return redirect(url_for('authenticate'))


def is_empty(field, form):
    key = 'html_{}'.format(field)
    value = form[key]
    empty = False
    if not len(value) > 0:
        empty = True
        flash('{} is empty'.format(field))
    return empty

app.run(debug=True)