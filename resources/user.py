from flask_restful import Resource, reqparse
from flask import request
from marshmallow import ValidationError
from models.user import UserModel
from werkzeug.security import safe_str_cmp
from flask_jwt_extended import create_access_token, create_refresh_token, jwt_required, get_jwt
from blacklist import BLACKLIST
from schemas.user import UserSchema


user_schema = UserSchema()
class UserRegister(Resource):
    @classmethod
    def post(cls):
        user = user_schema.load(request.get_json())

        if UserModel.find_by_username(user.username):
            return {"message": "A user with that username already exists"}, 400

        user.save_to_db()

        return {"message": "User created successfully."}, 201

class User(Resource):
    @classmethod
    @jwt_required()
    def get(cls, user_id:int):
        user = UserModel.find_by_id(user_id)
        if not user:
            return {'message':'User not found'}, 404
        return user_schema.dump(user), 200

    @classmethod
    @jwt_required()
    def delete(cls, user_id:int):
        claims = get_jwt()
        if not claims['is_admin']:
            return {'message':'Admin privilege required.'}, 401

        user = UserModel.find_by_id(user_id)
        if not user:
            return {'message':'User not found'}, 404
        user.delete_from_db()
        return {'message':'User deleted.'}, 200

class UserLogin(Resource):
    @classmethod
    def post(cls):
        user_json = request.get_json()
        user_data = user_schema.load(user_json)
        user = UserModel.find_by_username(user_data.username)
        if user and safe_str_cmp(user.password, user_data['password']):
            access_token = create_access_token(identity=user.id, fresh=True)
            refersh_token = create_refresh_token(user.id)
            return {
                'access_token' : access_token,
                'refersh_token' : refersh_token
            }, 200
        return {'message':'Invalid credentials'}, 401

class UserLogout(Resource):
    @classmethod
    @jwt_required()
    def post(cls):
        jwi = get_jwt()['jti']
        BLACKLIST.add(jwi)
        return {'message':'Successfully logged out.'}, 200

class TokenRefresh(Resource):
    @classmethod
    @jwt_required(refresh=True)
    def post(cls):
        current_user = get_jwt()
        new_token = create_access_token(identity=current_user, fresh=False)
        return {'access_token':new_token}, 200