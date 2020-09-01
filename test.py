from flask import Flask, render_template, request, make_response, jsonify, session
from flask_mysqldb import MySQL
import jwt
from functools import wraps
import datetime

app = Flask(__name__)

app.config['SECRET_KEY'] = 'JustDemonstrating'

def check_for_token(func):
    @wraps(func)
    def wrapped(*args, **kwargs):
        token = request.args.get('token')
        if not token:
            return jsonify({'message':'Missing Token'}), 403
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
        except:
            return jsonify({'message':'Invalid token'}), 403
        return func(*args, **kwargs)
    return wrapped

@app.route('/')
def index():
    if not session.get('logged_in'):
        return render_template('index.html')
    else:
        return 'Currently logged in'

@app.route('/public')
def public():
    return 'Anyone can view this'

@app.route('/auth')
@check_for_token
def authorized():
    return 'This is only viewable with a token'


# app.config['MYSQL_HOST'] = '127.0.0.1'
# app.config['MYSQL_USER'] = 'root' 
# app.config['MYSQL_PASSWORD'] = '123'
# app.config['MYSQL_DB'] = 'fresher_flask'
# mysql = MySQL(app)

@app.route('/login', methods=['POST'])
def login():
    if request.form['username'] and request.form['password'] == 'password':
        session['logged_in'] = True
        token = jwt.decode({
            'user' : request.form['username'],
            'exp' : datetime.datetime.now() + datetime.timedelta(seconds=60)
        },
        app.config['SECRET_KEY'])
        return jsonify({'token' : token.decode('utf-8')})
    else:
        return make_response('Unable to verify', 403, {'WWW-Authenticate': 'Basic realm:'})

    # if request.method == "POST":
    #     details = request.form
    #     username = details['username']
    #     password = details['password']
    #     cur = mysql.connection.cursor()
    #     cur.execute("INSERT INTO user_profile(username, password)" " VALUES (%s, %s)", (username, password))
    #     mysql.connection.commit()
    #     cur.close()
    #     return 'success'
    # return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)