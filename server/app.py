#!/usr/bin/env python3
from flask import request, session
from flask_restful import Resource, Api
from config import app, db
from models import User
from flask_cors import CORS

api = Api(app)
CORS(app)

class Signup(Resource):
    
    def post(self):
        json_data = request.get_json()
        username = json_data.get('username')
        password = json_data.get('password')

        # Check if username or password is missing
        if not username or not password:
            return {'error': 'Username and password are required'}, 400

        # Check if the username already exists
        if User.query.filter_by(username=username).first():
            return {'error': 'Username already exists'}, 400

        # Create a new user and save it to the database
        user = User(username=username)
        user.password_hash = password
        db.session.add(user)
        db.session.commit()

        # Save user ID in the session
        session['user_id'] = user.id

        # Return the user object in the JSON response
        return user.to_dict(), 201

class CheckSession(Resource):
    
    def get(self):
        if 'user_id' in session:
            user = User.query.get(session['user_id'])
            if user:
                return user.to_dict(), 200

        # If user is not authenticated, return empty response with 204 status code
        return {}, 204
class Login(Resource):
    
    def post(self):
        json_data = request.get_json()
        username = json_data.get('username')
        password = json_data.get('password')

        # Retrieve user from the database based on the username
        user = User.query.filter_by(username=username).first()

        # Check if user exists and authenticate password
        if user and user.authenticate(password):
            # Save user ID in the session
            session['user_id'] = user.id
            return user.to_dict(), 200

        # If authentication fails, return error response
        return {'error': 'Invalid username or password'}, 401

class Logout(Resource):
    
    def delete(self):
        # Clear user ID from the session
        session.pop('user_id', None)
        return {}, 204


class ClearSession(Resource):

    def delete(self):
    
        session['page_views'] = None
        session['user_id'] = None

        return {}, 204

class Signup(Resource):
    
    def post(self):
        json = request.get_json()
        user = User(
            username=json['username']
        )
        user.password_hash = json['password']
        db.session.add(user)
        db.session.commit()
        return user.to_dict(), 201

#class CheckSession(Resource):
   # pass

#class Login(Resource):
   # pass

#class Logout(Resource):
  #  pass

api.add_resource(ClearSession, '/clear', endpoint='clear')
api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')


if __name__ == '__main__':
    app.run(port=5555, debug=True)
