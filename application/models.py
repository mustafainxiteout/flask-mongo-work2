import flask
from application import db
import datetime
from bson.timestamp import Timestamp

class Usecase(db.Document):
    usecase_name = db.StringField(required=True, unique=True)
    heading = db.StringField(required=True)
    usecase_desc = db.StringField()
    disp_order = db.IntField()
    nav_link = db.StringField(required=True)
    created_id = db.StringField()
    created_dt = db.DateTimeField(default=datetime.datetime.utcnow())
    status = db.BooleanField(default=True)
    modify_id = db.StringField()
    modify_dt = db.DateTimeField()
    label = db.DictField()
    ucid = db.StringField(required=True, unique=True)