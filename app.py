import datetime
import os
from flask import Flask, jsonify, request, abort
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = "postgresql://ss_db_render_postgre_user:A6ez4LlcojQ0NEdogSY9WfbyVgAviixL@dpg-cigefq5gkuvojj8rods0-a.oregon-postgres.render.com/ss_db_render_postgre"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'secret'
CORS(app)
db = SQLAlchemy(app)


def encode_auth_token(user_id, user_email):
    try:
        payload = {
            # 'exp': datetime.datetime.utcnow() + datetime.timedelta(days=0, seconds=3600),
            # 'iat:': datetime.datetime.utcnow(),
            'sub': user_id,
            'email': user_email
        }
        return jwt.encode(payload, app.config.get('JWT_SECRET_KEY'), algorithm='HS256')
    except Exception as e:
        print(e, "<-----------------------")
        return e


def decode_auth_token(auth_token):
    try:
        payload = jwt.decode(auth_token, app.config.get(
            'JWT_SECRET_KEY'), algorithms='HS256')
        return payload['sub']
    except jwt.ExpiredSignatureError:
        return 'Signature expired. Please log in again.'
    except jwt.InvalidTokenError:
        return 'Invalid token. Please log in again.'


# create funtion to validate token header
# def validate_token():
#     auth_header = request.headers.get("Authorization")
#     if auth_header:
#         auth_token = auth_header.split(" ")[1]
#     else:
#         return jsonify({"msg": "Token is missing"}), 403

#     print("token valido")
#     response = decode_auth_token(auth_token)


@app.route('/')
def hello_world():
    return 'Hello, World!'


@app.route('/signup', methods=['POST'])
def signUp():

    data = request.get_json()

    user = User.query.filter_by(email=data["email"]).first()

    if user:
        return jsonify({"msg": "User already exists"}), 401

    hashed_password = generate_password_hash(data["password"], method='sha256')

    newUser = User(email=request.json["email"],
                   password=hashed_password,
                   name=request.json["name"],
                   lastname=request.json["lastname"]
                   )

    db.session.add(newUser)
    db.session.commit()

    auth_token = encode_auth_token(newUser.id, newUser.email)
    return jsonify("token:", auth_token), 201


@app.route("/login", methods=["POST"])
def login():

    data = request.get_json()

    user = User.query.filter_by(email=data["email"]).first()
    if user is None:
        return jsonify({"msg": "Bad username or password"}), 404

    if check_password_hash(user.password, data["password"]):
        auth_token = encode_auth_token(user.id, user.email)
        return jsonify({"auth_token": auth_token, "id": user.id}), 200

    else:
        return jsonify(message="Wrong credentials"), 401


@app.route("/validate", methods=["POST"])
def validate():
    data = request.get_json()
    token = data["token"]

    try:
        payload = jwt.decode(token, app.config.get(
            'JWT_SECRET_KEY'), algorithms=['HS256'])
        user = User.query.filter_by(id=payload["sub"]).first()

        if user:
            return jsonify(valid=True, user=user.serialize()), 200
        else:
            return jsonify(valid=False, message="User not found"), 200

    except jwt.ExpiredSignatureError:
        return jsonify(valid=False, message="Signature expired. Please log in again."), 200
    except jwt.InvalidTokenError:
        return jsonify(valid=False, message="Invalid token. Please log in again."), 200


@app.route('/user', methods=['GET'])
def get_users():

    users = User.query.all()
    return jsonify([user.serialize() for user in users]), 200


@app.route('/user/<string:item_id>', methods=['GET'])
def get_user(item_id):

    auth_header = request.headers.get("Authorization")

    if auth_header:
        auth_token = auth_header.split(" ")[1]

    else:
        return jsonify({"msg": "Token is missing"}), 403

    response = decode_auth_token(auth_token)

    user = User.query.get(item_id)
    if user is None:
        abort(404)
    return jsonify(user.serialize()), 200


@app.route('/canchas', methods=['GET'])
def get_canchas():

    canchas = Canchas.query.all()
    return jsonify([cancha.serialize() for cancha in canchas]), 200


@app.route('/canchas/<string:item_id>', methods=['GET'])
def get_cancha(item_id):

    cancha = Canchas.query.get(item_id)
    if cancha is None:
        abort(404)
    return jsonify(cancha.serialize()), 200


@app.route('/canchas', methods=["POST"])
def create_canchas():
    print(request.json)
    cancha = Canchas(name=request.json["name"],
                     location=request.json["location"],
                     user_id=request.json["user_id"],
                     sportType=request.json["sportType"],
                     cantidad=request.json["cantidad"]
                     )
    print(cancha)
    db.session.add(cancha)
    db.session.commit()

    return jsonify(cancha.serialize()), 200


rentas_user = db.Table(
    "rentas_user",
    db.Column('user_id', db.Integer, db.ForeignKey('user.id')),
    db.Column('rentas_id', db.Integer, db.ForeignKey('rentas.id'))
)

canchas_rentas = db.Table(
    "canchas_rentas",
    db.Column('rentas_id', db.Integer, db.ForeignKey('canchas.id')),
    db.Column('canchas_id', db.Integer, db.ForeignKey('rentas.id'))
)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=True)
    name = db.Column(db.String(120), nullable=True)
    lastname = db.Column(db.String(120), nullable=True)
    password = db.Column(db.String(500), nullable=True)
    is_admin = db.Column(db.Boolean, nullable=True)
    is_renter = db.Column(db.Boolean, nullable=True)
    rentas = db.relationship(
        'Rentas', secondary=rentas_user, back_populates='users')

    def serialize(self):
        return {
            "id": self.id,
            "email": self.email,
            "name": self.name,
            "lastname": self.lastname,
            "is_admin": self.is_admin,
            "is_renter": self.is_renter
        }


class Canchas(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    location = db.Column(db.String, nullable=False)
    name = db.Column(db.String(120), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    sportType = db.Column(db.String, nullable=False)
    cantidad = db.Column(db.Integer, nullable=False)
    user = db.relationship('User', backref='canchas')
    rentas = db.relationship(
        'Rentas', secondary=canchas_rentas, back_populates='canchas')

    def serialize(self):
        return {
            "id": self.id,
            "location": self.location,
            "name": self.name,
            "sportType": self.sportType,
            "cantidad": self.cantidad,
            "user_id": self.user_id
        }


class Rentas(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    disponibility = db.Column(db.DateTime, nullable=False)
    is_available = db.Column(db.Boolean, nullable=False)
    counter = db.Column(db.Boolean, nullable=False)
    users = db.relationship(
        'User', secondary=rentas_user, back_populates='rentas')
    canchas = db.relationship(
        'Canchas', secondary=canchas_rentas, back_populates='rentas')

    def serialize(self):
        return {
            "id": self.id,
            "disponibility": self.disponibility,
            "is_available": self.is_available,
            "counter": self.counter
        }


if __name__ == '__main__':
    app.run(debug=True)
