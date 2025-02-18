import datetime
import os
import re
from flask import Flask, jsonify, request, abort
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS


app = Flask(__name__)
DBURL = os.getenv("DATABASE_URL")
secret = os.getenv("JWT_SECRET_KEY")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
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


@app.route('/')
def hello_world():
    return 'Hello, World!'


@app.route('/signup', methods=['POST'])
def signUp():

    data = request.get_json()

    user = User.query.filter_by(email=data["email"]).first()

    if user:
        return jsonify({"error": "User already exists"}), 401
    if not data.get("password") or not data.get("email") or not data.get("name") or not data.get("lastname"):
        return jsonify({"error": "Incomplete data provided"}), 401
    if not re.match(r"[^@]+@[^@]+\.[^@]+", data["email"]):
        return jsonify({"error": "Invalid email format"}), 401


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
    if users is None:
        return jsonify({"msg": "User not found"}), 404


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


@app.route('/canchas/<string:item_id>', methods=['PUT'])
def update_cancha(item_id):
    
        cancha = Canchas.query.get(item_id)
        if cancha is None:
            abort(404)
    
        cancha.location = request.json["location"]
        cancha.region = request.json["region"]
        cancha.comuna = request.json["comuna"]
        cancha.name = request.json["name"]
        cancha.apertura = request.json["apertura"]
        cancha.cierre = request.json["cierre"]
        cancha.is_available = request.json["is_available"]
        cancha.sportType = request.json["sportType"]
        cancha.cantidadCanchas = request.json["cantidadCanchas"]
        cancha.detalle = request.json["detalle"]
        cancha.precio = request.json["precio"]
        cancha.user_id = request.json["user_id"]
        cancha.img = request.json["img"]
        # cancha.rentas = request.json["rentas"]
    
        db.session.commit()
    
        return jsonify(cancha.serialize()), 200

@app.route('/canchas/<string:item_id>', methods=['DELETE'])
def delete_cancha(item_id):
    cancha = Canchas.query.get(item_id)
    if cancha is None:
        abort(404)

    db.session.delete(cancha)
    db.session.commit()

    return jsonify({"success": "Cancha deleted"}), 200

@app.route('/canchas/<string:item_id>', methods=['GET'])
def get_cancha(item_id):

    cancha = Canchas.query.get(item_id)
    if cancha is None:
        abort(404)
    return jsonify(cancha.serialize()), 200


@app.route('/canchas', methods=["POST"])
def create_canchas():
    cancha = Canchas(
                     location=request.json["location"],
                     region=request.json["region"],
                     comuna=request.json["comuna"],
                     name=request.json["name"],
                     apertura=request.json["apertura"],
                     cierre=request.json["cierre"],
                     is_available=request.json["is_available"],
                     sportType=request.json["sportType"],
                     cantidadCanchas=request.json["cantidadCanchas"],
                     detalle=request.json["detalle"],
                     precio=request.json["precio"],
                     user_id=request.json["user_id"],
                     img=request.json["img"],
                    #  rentas=request.json["rentas"]
                     )
    print(cancha)
    db.session.add(cancha)
    db.session.commit()

    return jsonify(cancha.serialize()), 200

@app.route('/users/<int:user_id>/canchas', methods=['GET'])
def get_user_canchas(user_id):
    user = User.query.get(user_id)

    if user is None:
        return jsonify({'error': 'User not found'}), 404

    canchas = user.canchas
    canchas_data = [cancha.serialize() for cancha in canchas]

    return jsonify(canchas_data), 200

@app.route('/users/<int:user_id>/rentas', methods=['GET'])
def get_user_rentas(user_id):
    user = User.query.get(user_id)

    if user is None:
        return jsonify({'error': 'User not found'}), 404

    rentas = user.rentas
    rentas_data = [rentas.serialize() for renta in rentas]

    return jsonify(rentas_data), 200

@app.route('/rentas', methods=['POST'])
def create_rentas():
    newRentas = Rentas(
                       time=request.json["time"],
                       date=request.json["date"],
                       contadorArriendo=request.json["contadorArriendo"],
                       user_id=request.json["user_id"],
                       cancha_id=request.json["cancha_id"]
                       )

    db.session.add(newRentas)
    db.session.commit()

    return jsonify(newRentas.serialize()), 200


@app.route('/rentas', methods=['GET'])
def get_rentas():

    rentas = Rentas.query.all()
    return jsonify([renta.serialize() for renta in rentas]), 200


rentas_user = db.Table(
    "rentas_user",
    db.Column('user_id', db.Integer, db.ForeignKey('user.id')),
    db.Column('rentas_id', db.Integer, db.ForeignKey('rentas.id'))
)

canchas_rentas = db.Table(
    "canchas_rentas",
    db.Column('rentas_id', db.Integer, db.ForeignKey('rentas.id')),
    db.Column('canchas_id', db.Integer, db.ForeignKey('canchas.id'))
)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=True)
    name = db.Column(db.String(120), nullable=True)
    lastname = db.Column(db.String(120), nullable=True)
    password = db.Column(db.String(500), nullable=True)
    img = db.Column(db.String(500), nullable=True)
    is_admin = db.Column(db.Boolean, nullable=True)
    is_renter = db.Column(db.Boolean, nullable=True)
    canchas = db.relationship('Canchas', backref='user', lazy=True)
    rentas = db.relationship('Rentas',  backref='user', lazy=True)


    def serialize(self):
        return {
            "id": self.id,
            "email": self.email,
            "name": self.name,
            "lastname": self.lastname,
            "is_admin": self.is_admin,
            "is_renter": self.is_renter,
            "img" : self.img,
            "canchas": [cancha.serialize() for cancha in self.canchas],
            "rentas": [renta.serialize() for renta in self.rentas],
        }


class Canchas(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    location = db.Column(db.String, nullable=True)
    region = db.Column(db.String, nullable=True)
    comuna = db.Column(db.String, nullable=True)
    name = db.Column(db.String(120), nullable=True)
    is_available = db.Column(db.Boolean, nullable=False)
    sportType = db.Column(db.String, nullable=True)
    img = db.Column(db.String(500), nullable=True)
    apertura = db.Column(db.Integer, nullable=True)
    cierre = db.Column(db.Integer, nullable=True)
    cantidadCanchas = db.Column(db.Integer, nullable=True)
    detalle = db.Column(db.String, nullable=True)
    precio = db.Column(db.Integer, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    rentas = db.relationship('Rentas', secondary=canchas_rentas, backref='canchas')

    def serialize(self):
        return {
            "id": self.id,
            "location": self.location,
            "region": self.region,
            "comuna": self.comuna,
            "name": self.name,
            "apertura": self.apertura,
            "cierre": self.cierre,
            "sportType": self.sportType,
            "cantidad": self.cantidadCanchas,
            "detalle": self.detalle,
            "is_available": self.is_available,
            "precio": self.precio,
            "img": self.img,
            "user_id": self.user_id,
            "rentas": self.rentas,
            "rentas": [renta.serialize() for renta in self.rentas],
        }


class Rentas(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    time = db.Column(db.Integer, nullable=True)
    date = db.Column(db.String, nullable=True)
    contadorArriendo = db.Column(db.Integer, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    cancha_id = db.Column(db.Integer, db.ForeignKey('canchas.id'), nullable=True)

    def serialize(self):
        return {
            "id": self.id,
            "date": self.date,
            "time": self.time,
            "cantidad": self.contadorArriendo,
            "user_id": self.user_id,
            "cancha_id": self.cancha_id
        }

if __name__ == '__main__':
    app.run(debug=True)
