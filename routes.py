# import os
# import datetime
# from flask import Flask, jsonify, request, abort, Blueprint
# from models import User, Canchas, Rentas
# from app import app, db, encode_auth_token, decode_auth_token
# from werkzeug.security import generate_password_hash, check_password_hash
# from jwt import jwt

# api = Flask(__name__)


# @api.route('/signup', methods=['POST'])
# def signUp():

#     data = request.get_json()

#     user = User.query.filter_by(email=data["email"]).first()

#     if user:
#         return jsonify({"msg": "User already exists"}), 401

#     hashed_password = generate_password_hash(data["password"], method='sha256')

#     newUser = User(email=request.json["email"],
#                    password=hashed_password,
#                    name=request.json["name"],
#                    lastname=request.json["lastname"]
#                    )
#     db.session.add(newUser)
#     db.session.commit()

#     return jsonify(newUser.serialize()), 200


# @api.route("/login", methods=["POST"])
# def login():

#     data = request.get_json()

#     user = User.query.filter_by(email=data["email"]).first()
#     if user is None:
#         return jsonify({"msg": "Bad username or password"}), 404

#     if check_password_hash(user.password, data["password"]):
#         print("funcionaa!!!!")
#         auth_token = encode_auth_token(user.id, user.email)
#         return jsonify(auth_token=auth_token), 200

#     else:
#         return jsonify(message="Wrong credentials"), 401


# # crear endpoint protected
# @api.route("/protected", methods=["GET"])
# def protected():
#     auth_header = request.headers.get("Authorization")
#     if auth_header:
#         auth_token = auth_header.split(" ")[1]
#     else:
#         return jsonify({"msg": "No token provided"}), 403

#     user_id = decode_auth_token(auth_token)
#     if isinstance(user_id, str):
#         return jsonify({"msg": user_id}), 401

#     user = User.query.filter_by(id=user_id).first()
#     if not user:
#         return jsonify({"msg": "User not found"}), 404

#     return jsonify(msg='success!', user=user.serialize()), 200


# @api.route('/user', methods=['GET'])
# def get_users():

#     users = User.query.all()
#     return jsonify([user.serialize() for user in users]), 200


# @api.route('/user/<string:item_id>', methods=['GET'])
# def get_user(item_id):

#     user = User.query.get(item_id)
#     if user is None:
#         abort(404)
#     return jsonify(user.serialize()), 200


# @api.route('/canchas', methods=['GET'])
# def get_canchas():

#     canchas = Canchas.query.all()
#     return jsonify([cancha.serialize() for cancha in canchas]), 200


# @api.route('/canchas', methods=["POST"])
# def create_canchas():
#     print(request.json)
#     cancha = Canchas(name=request.json["name"],
#                      location=request.json["location"],
#                      user_id=request.json["user_id"],
#                      sportType=request.json["sportType"],
#                      cantidad=request.json["cantidad"]
#                      )
#     print(cancha)
#     db.session.add(cancha)
#     db.session.commit()

#     return jsonify(cancha.serialize()), 200


# @api.route('/canchas/<string:item_id>', methods=['GET'])
# def get_cancha(item_id):

#     cancha = Canchas.query.get(item_id)
#     if cancha is None:
#         abort(404)
#     return jsonify(cancha.serialize()), 200
