from flask import Flask, jsonify
from flask_restful import Api
from flask_jwt_extended import JWTManager
from marshmallow import ValidationError
from resources.user import UserRegister, User, UserLogin, TokenRefresh, UserLogout
from resources.item import Item, ItemList
from resources.store import Store, StoreList
from blacklist import BLACKLIST
from ma import ma
import os, redis, socket

app = Flask(__name__)
app.secret_key = 'jose'
uri = os.getenv("DATABASE_URL")
if uri.startswith("postgres://"):
    uri = uri.replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_DATABASE_URI'] = uri
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PROPAGATE_EXCEPTIONS'] = True
app.config['JWT_BLACKLIST_ENABLED'] = True
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access', 'refresh']
api = Api(app)

@app.errorhandler(ValidationError)
def handle_marshmallow_validation(err):
    return jsonify(err.messages), 400

jwt = JWTManager(app)
running_port = 5000

@jwt.additional_claims_loader
def add_claims_to_jwt(identity):
    if identity == 1:
        return {'is_admin':True}
    return {'is_admin':False}

@jwt.token_in_blocklist_loader
def check_if_token_in_blacklist(jwt_header, jwt_payload):
    jti = jwt_payload["jti"]
    return jti in BLACKLIST

@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    return jsonify({'description':'The token has expired.', 'error':'token_expired'}), 401

@jwt.invalid_token_loader
def invalid_token_callback(jwt_header, jwt_payload):
    return jsonify({'description':'Signature verification failed.', 'error':'invalid_token'}), 401

@jwt.unauthorized_loader
def missing_token_callback(jwt_header, jwt_payload):
    return jsonify({'description':'Request does not contain an access token.', 'error':'authorization_required'}), 401

@jwt.needs_fresh_token_loader
def token_notfresh_callback(jwt_header, jwt_payload):
    return jsonify({'description':'The token is not fresh.', 'error':'fresh_token_required'}), 401

@jwt.revoked_token_loader
def revoked_token_callback(jwt_header, jwt_payload):
    return jsonify({'description':'The Token has  been revoked.', 'error':'token_revoked'}), 401

api.add_resource(Item, '/item/<string:name>')
api.add_resource(Store, '/store/<string:name>')
api.add_resource(ItemList, '/items')
api.add_resource(StoreList, '/stores')
api.add_resource(UserRegister, '/register')
api.add_resource(User, '/user/<int:user_id>')
api.add_resource(UserLogin, '/login')
api.add_resource(TokenRefresh, '/refresh')
api.add_resource(UserLogout, '/logout')


if __name__ == '__main__':
    from db import db
    db.init_app(app)
    ma.init_app(app)
    app.run(port=running_port, debug=True)