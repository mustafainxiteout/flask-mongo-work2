#Importing necessary libraries
from application import app,db,api
from flask import render_template, jsonify
from application.models import Usecase
from flask_restx import Resource,fields
import os
from datetime import datetime

#Creating a namespace for our API
ns2 = api.namespace('usecases', description='The usecases namespace provides endpoints for managing usecases, including creating, retrieving, updating, and deleting usecase information.')

# Define the expected payload using the 'fields' module
usecase_model = ns2.model('UsecaseModel', {
    'usecase_name': fields.String(required=True, description='Name of the usecase in upper case and unique'),
    'heading': fields.String(required=True, description='Short text for the usecase'),
    'usecase_desc': fields.String(required=True, description='Long text description of the usecase'),
    'disp_order': fields.Integer(required=True, description='Numeric display order of the usecase'),
    'nav_link': fields.String(required=True, description='Navigation link for the usecase'),
    'created_id': fields.String(required=True, description='Logged in user ID'),
    'status': fields.Boolean(description='Status of the usecase. True for active and False for inactive.'),
    'modify_id': fields.String(description='Modify ID user ID'),
    'label': fields.Nested(ns2.model('LabelModel', {
        'level1': fields.String(required=True, description='Level 1 label for the usecase'),
        'level2': fields.String(required=True, description='Level 2 label for the usecase')
    }), required=True, description='Label object for the usecase'),
    'ucid': fields.String(required=True, description='UCID for the usecase')
})


#Defining endpoints for getting and posting usecases
@ns2.route('')
class GetAndPost(Resource):
    def get(self):
        return jsonify(Usecase.objects.all())
    
    @ns2.expect(usecase_model)  # Use the 'expect' decorator to specify the expected payload
    def post(self):
        data=api.payload
        usecase=Usecase(usecase_name=data['usecase_name'].upper(),
            heading=data['heading'],
            usecase_desc=data['usecase_desc'],
            disp_order=data['disp_order'],
            nav_link=data['nav_link'],
            created_id=data['created_id'],
            status=data.get('status', True),
            modify_id=data.get('modify_id', None),
            modify_dt=datetime.utcnow() if data.get('modify_id') else None,
            label=data['label'],
            ucid=data['ucid'])
        usecase.save()
        return jsonify(Usecase.objects(ucid=data['ucid']))

#Defining endpoints for getting, updating and deleting usecases by ID
@ns2.route('/<idx>')
class GetUpdateDelete(Resource):
   
    def get(self,idx):
        return jsonify(Usecase.objects(ucid=idx))
    
    @ns2.expect(usecase_model)  # Use the 'expect' decorator to specify the expected payload
    def put(self,idx):
        data=api.payload
        Usecase.objects(ucid=idx).update(**data)
        return jsonify(Usecase.objects(ucid=idx))
    
    def delete(self,idx):
        Usecase.objects(ucid=idx).delete()
        return jsonify("Course is deleted!")
    

#Defining the route for the index page
@app.route("/")
@app.route("/index/")
def index():
    return render_template("index.html")