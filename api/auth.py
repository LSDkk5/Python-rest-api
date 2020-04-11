from flask import request, jsonify, Blueprint, abort
from flask_restful import Resource
from flask_login import login_user
from flask_jwt_extended import create_access_token, jwt_required
from datetime import timedelta

from api import bcrypt, User, api

class Register(Resource):
    def post(self):
        registerData = {'username': request.json['username'], 'password': request.json['password'],
            'email': request.json['email']}
        if not registerData['username'] or not registerData['password'] or not registerData['email']:
            return jsonify(message='Missing parameters')
        if User.objects(username=registerData['username']).first():
            return jsonify(message='This user already exist!')
        if User.objects(email=registerData['email']).first():
            return jsonify(message='This email address is already used, please use other')
        User(password=bcrypt.generate_password_hash(registerData['password']), 
                username=registerData['username'], email=registerData['email']).save()
        return jsonify(message='User successful created!')

class Login(Resource):
    def post(self):
        print(request.json)
        if request.json is None: return jsonify(message='Missing parameters')
        loginData = {'username': request.json['username'], 'password': request.json['password']}
        if loginData['username'] is None or loginData['password'] is None: 
            return jsonify(message='Missing parameters')
        user = User.objects(username=loginData['username']).first()
        if user and bcrypt.check_password_hash(user.password, loginData['password']):
            login_user(user)
            return jsonify(access_token=create_access_token(identity=user.username, 
                expires_delta=timedelta(minutes=30)), message='Succesfull log in!')
        return jsonify(message='Bad username or password!')