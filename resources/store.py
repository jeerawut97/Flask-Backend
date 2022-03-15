from flask_restful import Resource
from models.store import StoreModel
from flask_jwt_extended import jwt_required, get_jwt

class Store(Resource):
    @jwt_required()
    def get(self, name):
        store = StoreModel.find_by_name(name)
        if store:
            return store.json()
        return {'message': 'Store not found'}, 404

    @jwt_required()
    def post(self, name):
        if StoreModel.find_by_name(name):
            return {'message': "A store with name '{}' already exists.".format(name)}, 400

        store = StoreModel(name)
        try:
            store.save_to_db()
        except:
            return {"message": "An error occurred creating the store."}, 500

        return store.json(), 201

    @jwt_required()
    def delete(self, name):
        store = StoreModel.find_by_name(name)
        if store:
            store.delete_from_db()

        return {'message': 'Store deleted'}

class StoreList(Resource):
    @jwt_required(optional=True)
    def get(self):
        user_id = get_jwt()
        items = [item.json() for item in StoreModel.find_all()]
        if user_id:
            return {'stores':items}, 200
        return {
            'items': [item['name'] for item in StoreModel.find_all()],
            'message': 'More data available if you log in.'
        }, 200
