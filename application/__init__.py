#Importing necessary modules
from flask import Flask
from config import Config
from flask_mongoengine import MongoEngine
from flask_restx import Api

#Initializing the Flask app and configuring it using the Config class
app=Flask(__name__)
app.config.from_object(Config)

#Initializing the MongoEngine object and binding it to the Flask app instance
db=MongoEngine()
db.init_app(app)

#Initializing the Flask-RESTX API object and binding it to the Flask app instance
api=Api()
api.init_app(app)

#Importing the routes module where the app routes are defined
from application import routes 