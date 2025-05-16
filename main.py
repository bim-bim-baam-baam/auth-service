import os
from flask import Flask, request, jsonify, redirect
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from dotenv import load_dotenv
from flasgger import Swagger, swag_from

from providers.google import google_oauth

load_dotenv()

app = Flask(__name__)
Swagger(app)

POSTGRES_USER = os.getenv("POSTGRES_USER")
POSTGRES_PASSWORD = os.getenv("POSTGRES_PASSWORD")
POSTGRES_DB = os.getenv("POSTGRES_DB")
POSTGRES_HOST = os.getenv("POSTGRES_HOST")
POSTGRES_PORT = os.getenv("POSTGRES_PORT")
SECRET_KEY = os.getenv("SECRET_KEY")
PORT = os.getenv("PORT")

app.config['SQLALCHEMY_DATABASE_URI'] = (
    f"postgresql://{POSTGRES_USER}:{POSTGRES_PASSWORD}@{POSTGRES_HOST}:{POSTGRES_PORT}/{POSTGRES_DB}"
)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = SECRET_KEY

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

@app.route('/api/auth/basic/register', methods=['POST'])
@swag_from({
    'tags': ['Auth'],
    'description': 'Register a new user',
    'parameters': [
        {
            'name': 'body',
            'in': 'body',
            'required': True,
            'schema': {
                'type': 'object',
                'properties': {
                    'login': {'type': 'string'},
                    'password': {'type': 'string'}
                },
                'required': ['login', 'password']
            }
        }
    ],
    'responses': {
        201: {'description': 'User registered successfully'},
        400: {'description': 'Missing data or user already exists'}
    }
})
def register():
    data = request.get_json()
    login = data.get('login')
    password = data.get('password')

    if not login or not password:
        return jsonify({'error': 'Login and password required'}), 400

    if User.query.filter_by(login=login).first():
        return jsonify({'error': 'User already exists'}), 400

    user = User(login=login)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()

    return jsonify({'message': 'User registered successfully'}), 201

@app.route('/api/auth/basic/login', methods=['POST'])
@swag_from({
    'tags': ['Auth'],
    'description': 'Authenticate user and get JWT token',
    'parameters': [
        {
            'name': 'body',
            'in': 'body',
            'required': True,
            'schema': {
                'type': 'object',
                'properties': {
                    'login': {'type': 'string'},
                    'password': {'type': 'string'}
                },
                'required': ['login', 'password']
            }
        }
    ],
    'responses': {
        200: {'description': 'JWT token'},
        400: {'description': 'Missing credentials'},
        401: {'description': 'Invalid credentials'}
    }
})

def login():
    data = request.get_json()
    login = data.get('login')
    password = data.get('password')

    if not login or not password:
        return jsonify({'error': 'Login and password required'}), 400

    user = User.query.filter_by(login=login).first()
    if not user or not user.check_password(password):
        return jsonify({'error': 'Invalid login or password'}), 401

    token = jwt.encode({
        'user_id': user.id,
        'exp': datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=24)
    }, app.config['SECRET_KEY'], algorithm='HS256')

    return jsonify({'token': token})

from flask import abort

@app.route('/api/auth/basic/verify', methods=['GET'])
@swag_from({
    'tags': ['Auth'],
    'description': 'Verify JWT token and get user info',
    'parameters': [
        {
            'name': 'Authorization',
            'in': 'header',
            'type': 'string',
            'required': True,
            'description': 'JWT token in format: Bearer <token>'
        }
    ],
    'responses': {
        200: {
            'description': 'Valid token',
            'schema': {
                'type': 'object',
                'properties': {
                    'user_id': {'type': 'integer'},
                    'login': {'type': 'string'}
                }
            }
        },
        401: {'description': 'Invalid or expired token'}
    }
})
def verify_token():
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'error': 'Authorization header missing or malformed'}), 401

    token = auth_header.split(' ')[1]
    try:
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user = User.query.get(data['user_id'])
        if not user:
            return jsonify({'error': 'User not found'}), 401

        return jsonify({'user_id': user.id, 'login': user.login})

    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token'}), 401
    

@app.route('/api/auth/google')
def login_google():
    uri, state = google_oauth.get_authorize_url()
    return redirect(uri)

@app.route('/api/auth/google/callback')
def google_callback():
    token = google_oauth.fetch_token(request.url)
    id_token = token['id_token']
    return jsonify({"id_token": id_token})

@app.route("/api/auth/google/verify", methods=["POST"])
def google_verify():
    raise NotImplemented
    data = request.get_json()
    token = data.get("id_token")
    if not token:
        return jsonify({"error": "Missing id_token"}), 400

    try:
        idinfo = id_token.verify_oauth2_token(
            token,
            google_requests.Request(),
            google_oauth.client_id  
        )
        return jsonify({
            "email": idinfo.get("email"),
            "name": idinfo.get("name"),
            "picture": idinfo.get("picture"),
            "sub": idinfo.get("sub")
        })

    except ValueError:
        return jsonify({"error": "Invalid token"}), 401


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=PORT)
