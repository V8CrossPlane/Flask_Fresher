from flask import Flask, render_template, request, make_response, jsonify, session
import jwt
from functools import wraps
import datetime
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'randomtext'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:123@127.0.0.1/fresher_flask'

db = SQLAlchemy(app)

class user_profile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(255), unique=True)
    name = db.Column(db.String(255))
    password = db.Column(db.String(255))
    admin = db.Column(db.Boolean)

    # def __init__(self, public_id, username, password, admin): 
    #     self.public_id = public_id
    #     self.username = username
    #     self.password = password
    #     self.admin = admin

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        if not token:
            return jsonify({'message': 'token is missing'}), 401
        
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = user_profile.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message':'token is invalid'}), 401
        
        return f(current_user, *args, **kwargs)
    return decorated
@app.route('/user', methods=['GET'])
@token_required
def get_all_user(current_user):
    if not current_user.admin:
        return jsonify({'message':'cannot perfrom that function'})

    users = user_profile.query.all()

    output = []
    for user in users:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['username'] = user.name
        user_data['password'] = user.password
        user_data['admin'] = user.admin
        output.append(user_data)
    return jsonify({'users' : output})

@app.route('/user/<public_id>', methods=['GET'])
@token_required
def get_one_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({'message':'cannot perfrom that function'})

    user = user_profile.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'message' : 'no user found'})

    user_data = {}
    user_data['public_id'] = user.public_id
    user_data['username'] = user.name
    user_data['password'] = user.password
    user_data['admin'] = user.admin

    return jsonify({'user' : user_data})

@app.route('/user', methods=['POST'])
@token_required
def create_user(current_user):
    if not current_user.admin:
        return jsonify({'message':'cannot perfrom that function'})

    data = request.get_json()

    hashed_password = generate_password_hash(data['password'], method='sha256')
    new_user = user_profile(public_id=str(uuid.uuid4()), name=data['username'], password = hashed_password, admin=False)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message' : 'new user created'})

@app.route('/user/<public_id>', methods=['PUT'])
@token_required
def promote_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({'message':'cannot perfrom that function'})

    user = user_profile.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'message' : 'no user found'})
    user.admin = True
    db.session.commit()
    return jsonify({'message':'the user has been promoted'})

@app.route('/user/<public_id>', methods=['DELETE'])
@token_required
def delete_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({'message':'cannot perfrom that function'})
        
    user = user_profile.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({'message' : 'no user found'})
    
    db.session.delete(user)
    db.session.commit()
    return jsonify({'message' : 'the user has been deleted'})

@app.route('/login')
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('could not verify', 401, {'WWW-Authenticate':'Basic realm="Login required"'})
    
    user = user_profile.query.filter_by(name=auth.username).first()

    if not user:
        # return jsonify({'message':'no user found'})
        return make_response('Could not verify', 401, {'WWW-Authenticate':'Basic realm="Login required"'})

    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_id' : user.public_id, 
                            'exp' : datetime.datetime.now() + datetime.timedelta(minutes=5)
                            },app.config['SECRET_KEY'])

        return jsonify({'token' : token.decode('UTF-8')})
    return make_response('Could not verify', 401, {'WWW-Authenticate':'Basic realm="Login required"'})

if __name__ == '__main__':
    app.run(debug=True)