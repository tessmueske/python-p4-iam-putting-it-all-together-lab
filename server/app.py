#!/usr/bin/env python3

from flask import request, session, jsonify
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe
from bcrypt import hashpw, gensalt

class Signup(Resource):
    def post(self):

        data = request.get_json()

        username = data.get('username')
        bio = data.get('bio')
        image_url = data.get('image_url')
        password_hash = data['password']

        new_user = User(username=username, bio=bio, image_url=image_url)
        new_user.password_hash=password_hash

        try:
            db.session.add(new_user)
            db.session.commit()
            return new_user.to_dict(), 201

        except:
            return ("Error: Failed to create user"), 422

class CheckSession(Resource):
    def get(self):

        if 'user_id' not in session or session['user_id'] is None:
            return {"error": "Unauthorized"}, 401

        user_id = session['user_id']
        user = db.session.get(User, user_id)

        if user:
            return user.to_dict(), 200
        else:
            return {"error": "User not found"}, 404

class Login(Resource):
    def post(self):

        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        user = User.query.filter_by(username=username).first()

        if user and user.authenticate(password):
            session['user_id'] = user.id

            return {
                'id': user.id,
                'username': user.username,
                'image_url': user.image_url,
                'bio': user.bio
            }, 200

        else:

            return {'error': 'Invalid username or password'}, 401

class Logout(Resource):
    def delete(self):

        if 'user_id' in session and session['user_id'] is not None:
            session.pop('user_id', None)
            return '', 204 
        else:
            return {'error': 'Unauthorized request'}, 401


class RecipeIndex(Resource):
    def get(self):
        if 'user_id' not in session or session['user_id'] is None:
            return {'error': 'Unauthorized'}, 401
        
        recipes = Recipe.query.filter_by(user_id=session['user_id']).all()
        recipes_data = []
        
        for recipe in recipes:
            recipes_data.append({
                'title': recipe.title,
                'instructions': recipe.instructions,
                'minutes_to_complete': recipe.minutes_to_complete,
                'user': {
                    'username': recipe.user.username,
                    'bio': recipe.user.bio,
                    'image_url': recipe.user.image_url
                }
            })
        
        return recipes_data, 200

    def post(self):
        if 'user_id' not in session:
            return {'error': 'Unauthorized request'}, 401
        
        user = User.query.get(session['user_id'])
        if not user:
            return {'error': 'Unauthorized request'}, 401

        data = request.get_json()
        if not data or not all(x in data for x in ('title', 'instructions', 'minutes_to_complete')):
            return {'error': 'Missing required fields'}, 422

        try:
            recipe = Recipe(
                title=data['title'],
                instructions=data['instructions'],
                minutes_to_complete=data['minutes_to_complete'],
                user_id=session['user_id']
            )
            db.session.add(recipe)
            db.session.commit()
        except ValueError as e:
            return {'error': str(e)}, 422
        except Exception as e:

            app.logger.error(f"Unexpected error: {e}")
            return {'error': 'Internal server error'}, 500

        return {
            'title': recipe.title,
            'instructions': recipe.instructions,
            'minutes_to_complete': recipe.minutes_to_complete,
            'user': {
                'username': user.username,
                'bio': user.bio,
                'image_url': user.image_url
            }
        }, 201

api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)