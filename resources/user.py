from flask_restful import Resource, reqparse
from models.user import UserModel
from werkzeug.security import safe_str_cmp
from flask_jwt_extended import create_access_token, create_refresh_token, jwt_required, get_jwt
from blacklist import BLACKLIST

_user_parser = reqparse.RequestParser()
_user_parser.add_argument('username',
                    type=str,
                    required=True,
                    help="This field cannot be blank."
                    )
_user_parser.add_argument('password',
                    type=str,
                    required=True,
                    help="This field cannot be blank."
                    )

class UserRegister(Resource):
    @classmethod
    def post(cls):
        data = _user_parser.parse_args()

        if UserModel.find_by_username(data['username']):
            return {"message": "A user with that username already exists"}, 400

        user = UserModel(data['username'], data['password'])
        user.save_to_db()

        return {"message": "User created successfully."}, 201

class User(Resource):
    @classmethod
    @jwt_required()
    def get(cls, user_id:int):
        user = UserModel.find_by_id(user_id)
        if not user:
            return {'message':'User not found'}, 404
        return user.json()

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
        data = _user_parser.parse_args()
        user = UserModel.find_by_username(data['username'])
        if user and safe_str_cmp(user.password, data['password']):
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