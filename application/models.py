import flask
from application import db
from werkzeug.security import generate_password_hash, check_password_hash
import datetime
from bson.timestamp import Timestamp

class users(db.Document):
    user_id=db.IntField(unique=True)
    first_name=db.StringField(max_length=50)
    last_name=db.StringField(max_length=50)
    gender=db.StringField(max_length=8)
    email=db.StringField(max_length=50,unique=True)
    password=db.StringField()
    verified=db.BooleanField(default=False)
    created_at = db.DateTimeField(default=datetime.datetime.utcnow())

    def set_password(self, password):
        self.password=generate_password_hash(method='pbkdf2:sha512:150000',password=password)
    
    def get_password(self,password):
        return check_password_hash(self.password, password)
    
class Usecase(db.Document):
    usecase_name = db.StringField(required=True, unique=True)
    heading = db.StringField(required=True)
    usecase_desc = db.StringField()
    disp_order = db.IntField()
    nav_link = db.StringField(required=True, unique=True)
    created_id = db.StringField()
    created_dt = db.DateTimeField()
    status = db.BooleanField(default=True)
    modify_id = db.StringField()
    modify_dt = db.DateTimeField()
    label = db.DictField()
    ucid = db.StringField(required=True, unique=True)

class NewTableModel(db.Document):
    name = db.StringField(required=True)
    age = db.IntField(required=True)
    addresstype = db.StringField(required=True)
    t_id=db.IntField(unique=True)