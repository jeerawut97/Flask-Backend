from flask_restful import Resource
from models.store import StoreModel
from schemas.store import StoreSchema
from flask_jwt_extended import jwt_required, get_jwt

store_schema = StoreSchema()
store_list_schema = StoreSchema(many=True)
class Store(Resource):
    @classmethod
    @jwt_required()
    def get(cls, name:str):
        store = StoreModel.find_by_name(name)
        if store:
            return store_schema.dump(store)
        return {'message': 'Store not found'}, 404

    @classmethod
    @jwt_required()
    def post(cls, name:str):
        if StoreModel.find_by_name(name):
            return {'message': "A store with name '{}' already exists.".format(name)}, 400

        store = StoreModel(name=name)
        try:
            store.save_to_db()
        except:
            return {"message": "An error occurred creating the store."}, 500

        return store_schema.dump(store), 201

    @classmethod
    @jwt_required()
    def delete(cls, name:str):
        store = StoreModel.find_by_name(name)
        if store:
            store.delete_from_db()

        return {'message': 'Store deleted'}

class StoreList(Resource):
    @classmethod
    @jwt_required(optional=True)
    def get(cls):
        user_id = get_jwt()
        if user_id:
            return {'stores':store_list_schema.dump(StoreModel.find_all())}, 200
        return {
            'items': [item['name'] for item in StoreModel.find_all()],
            'message': 'More data available if you log in.'
        }, 200
