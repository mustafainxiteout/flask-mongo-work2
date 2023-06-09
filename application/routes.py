#Importing necessary libraries
from application import app,db,api,jwt,mail,serializer
from flask import render_template, jsonify, json, request, url_for, send_from_directory, send_file
from application.models import Usecase,users,NewTableModel,RemoteDocument
from flask_restx import Resource,fields
from flask_mail import Mail, Message
from werkzeug.utils import secure_filename
import os, re
from datetime import datetime
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from flask_jwt_extended import create_access_token,jwt_required,get_jwt_identity
from mongoengine.errors import NotUniqueError

#Creating a namespace for our API
ns = api.namespace('users', description='The users namespace contains endpoints for managing user data. This includes creating, retrieving, updating, and deleting user accounts, as well as managing user authentication and authorization.')

# Define the expected payload using the 'fields' module
user_model = ns.model('User', {
    'first_name': fields.String(required=True, description='enter your name'),
    'last_name': fields.String(required=True, description='enter your name'),
    'gender': fields.String(required=True, description='enter your name'),
    'email': fields.String(required=True, description='enter your email id'),
    'password': fields.String(required=True, description='enter your password')
})

login_model = ns.model('Login', {
    'email': fields.String(required=True, description='enter your email id'),
    'password': fields.String(required=True, description='enter your password')
})

password_model = ns.model('Password', {
    'password': fields.String(required=True, description='enter your password')
})

forgot_password_model = ns.model('ForgotPassword', {
    'email': fields.String(required=True, description='enter your email id'),
    'new_password': fields.String(required=True, description='enter your new password')
})

update_password_model = ns.model('UpdatePassword', {
    'old_password': fields.String(required=True, description='enter your old password'),
    'new_password': fields.String(required=True, description='enter your new password')
})

reverify_model = ns.model('Reverify', {
    'email': fields.String(required=True, description='enter your email id')
})


# Define the authorization header model
auth_header = api.parser()
auth_header.add_argument('Authorization', type=str, location='headers', required=True, help='Bearer Access Token')

def is_valid_password(password):
    # Minimum eight characters, at least one uppercase letter, one lowercase letter, one number and one special symbol
    pattern = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$'
    return bool(re.match(pattern, password))

@ns.route('')
class GetAndPostUser(Resource):
    @ns.doc(security='Bearer Auth', parser=auth_header)
    @jwt_required() # add this if you're using JWT for authentication
    def get(self):
        idx=get_jwt_identity()
        # Get user object by user_id and exclude password field
        user = users.objects.exclude('password').get(user_id=idx)
        # Serialize user object to JSON
        user_json = json.loads(user.to_json())
        return jsonify(user_json)
    
    @ns.expect(user_model)  # Use the 'expect' decorator to specify the expected payload
    def post(self):
        # Get request data from payload
        data=api.payload
        #increment user_id+1 and generate it automatically
        max_user_id = users.objects.aggregate({"$group": {"_id": None, "max_user_id": {"$max": "$user_id"}}}).next().get("max_user_id")
        userid = max_user_id + 1
        # Validate the password
        if not is_valid_password(data['password']):
            # Return an error response if the password is invalid
            return jsonify({'message': 'Invalid password.'}), 400
        elif not users.objects(email=data['email']).first():
            # Create a new user and hash password and then send verification link to mail
            verified=False
            user=users(user_id=userid,first_name=data['first_name'],last_name=data['last_name'],gender=data['gender'],email=data['email'],verified=verified)
            user.set_password(data['password'])
            user.save()
            emailid=data['email']
            token = serializer.dumps(emailid, salt='email-verification') 
            # create verification URL with token
            verification_url = f'http://localhost:8000/verify_email/{token}'
            # Render the email template with the verify URL
            html_body = render_template('verify_email.html', verify_url=verification_url, subject='Verify your account', button='VERIFY ACCOUNT',content='We are happy you signed up for Inxiteout. To start exploring Courses App, please confirm your email address.',caption='Didn’t create account')
            # create message and send email
            message = Message('Verify Your Email', recipients=[emailid])
            message.html = html_body
            mail.send(message)
            return {'message': 'Please click on the Verification Link Sent to mail'}, 200
        elif users.objects(email=data['email']).first():
            return {'message': 'User Account is already registered'}, 401
        else:
            return {'message': 'Error occured'}, 401
        
    @ns.expect(user_model, auth_header) 
    @ns.doc(security='Bearer Auth', parser=auth_header)
    @jwt_required() # add this if you're using JWT for authentication
     # Use the 'expect' decorator to specify the expected payload
    def put(self):
        # Get request data from payload
        data = api.payload
        idx=get_jwt_identity()
        user = users.objects(user_id=idx).first()
        unique_email=data.get('email', None)
        if user.verified==False:
            return jsonify({"error": "Not verified, Cant Update!"})
        else:
            try:
                # Exclude password field from update
                data.pop('password', None)
                if 'email' in data:
                    data['verified']=False
                users.objects(user_id=idx).update(**data)
                # Get updated user object and exclude password field
                userwithoutpassword = users.objects.exclude('password','verified').get(user_id=idx)
                # Serialize user object to JSON
                user_json = json.loads(userwithoutpassword.to_json())
                return jsonify(user_json)
            except NotUniqueError:
                return {'message': f'Email id - {unique_email} already exists'}, 400
        
    @ns.expect(password_model, auth_header)  # Use the 'expect' decorator to specify the expected payload
    @ns.doc(security='Bearer Auth', parser=auth_header)
    @jwt_required() # add this if you're using JWT for authentication
    def delete(self):
        # Get request data from payload
        data = api.payload
        idx=get_jwt_identity()
        user = users.objects(user_id=idx).first()
        # Verify user with password and then delete user account
        if not user.get_password(data['password']):
            return jsonify({"error": "Incorrect password"})
        elif user.verified==False:
            return jsonify({"error": "Not verified, Cant Delete!"})
        else:
            user.delete()
            return jsonify("User is deleted!")

    
@ns.route('/allusers')
class GetUpdateDeleteUser(Resource):
    @ns.doc(security='Bearer Auth', parser=auth_header)
    @jwt_required() # add this if you're using JWT for authentication
    def get(self):
        # Get all users and exclude password field
        return jsonify(users.objects.exclude('password','verified'))

    
@ns.route('/updatepassword')
class UpdateUserpassword(Resource):
    @ns.expect(update_password_model, auth_header)  # Use the 'expect' decorator to specify the expected payload
    @ns.doc(security='Bearer Auth', parser=auth_header)
    @jwt_required() # add this if you're using JWT for authentication
    def put(self):
        idx=get_jwt_identity()
        # Get request data from payload
        data=api.payload
        user=users.objects(user_id=idx).first()
        # Verify user with old password and then update new password
        if not user:
            return {'message': 'User not found'}, 404
        
        if not user.get_password(data['old_password']):
            return {'message': 'Incorrect password'}, 401
        
        if user.verified==False:
            return jsonify({"error": "Not verified, Cant Update!"})
        
        # Validate the password
        if not is_valid_password(data['new_password']):
            return jsonify({'message': 'Invalid password.'}), 400
            # Return an error response if the password is invalid
        
        user.set_password(data['new_password'])
        user.save()
        
        return {'message': 'User password updated successfully'}, 200
    
@ns.route('/reverify')
class Reverify(Resource):
    @ns.expect(reverify_model)  # Use the 'expect' decorator to specify the expected payload
    def post(self):
        # Get request data from payload
        data=api.payload
        user=users.objects(email=data['email']).first()
        if not user:
            return {'message': 'Invalid User'}, 401
        else:
            emailid=data['email']
            token = serializer.dumps(emailid, salt='email-verification') 
            # create verification URL with token
            verification_url = f'http://localhost:8000/verify_email/{token}'
            # Render the email template with the reverify URL
            html_body = render_template('verify_email.html', verify_url=verification_url, subject='Verify your account',button='VERIFY ACCOUNT',content='We are happy you signed up for Inxiteout. To start exploring Courses App, please confirm your email address.',caption='Didn’t create account')
            # create message and send email
            message = Message('Verify Your Email', recipients=[emailid])
            message.html = html_body
            mail.send(message)
            return {'message': 'Please click on the Verification Link Sent to mail'}, 200
        
@ns.route('/forgot_password')
class ForgotPassword(Resource):
    @ns.expect(forgot_password_model)  # Use the 'expect' decorator to specify the expected payload
    def post(self):
        # Get request data from payload
        data = api.payload
        user = users.objects(email=data['email']).first()
        if not user:
            return {'message': 'Invalid User'}, 401
        # Validate the password
        elif not is_valid_password(data['new_password']):
            # Return an error response if the password is invalid
            return jsonify({'message': 'Invalid password.'}), 400
        else:
            # Generate password reset token
            token = serializer.dumps(data, salt='password-reset')
            # Create password reset URL with token
            reset_url = f'http://localhost:8000/reset_password/{token}'
            # Render the email template with the reverify URL
            html_body = render_template('verify_email.html', verify_url=reset_url, subject='Forgot your Password', button='RESET PASSWORD', content='We noticed that you have requested to reset your password for your Inxiteout account. To proceed with this request, please click on the password reset button below.', caption='Didn’t reset password')
            # Create message and send email
            message = Message('Reset Your Password', recipients=[data['email']])
            message.html = html_body
            mail.send(message)
            return {'message': 'Please check your email for password reset instructions'}, 200        
    
@ns.route('/login')
class Login(Resource):
    @ns.expect(login_model)  # Use the 'expect' decorator to specify the expected payload
    def post(self):
        # Get request data from payload
        data=api.payload
        user=users.objects(email=data['email']).first()
        
        if not user or user.verified==False or not user.get_password(data['password']):
            return {'message': 'Invalid credentials'}, 401
        
        else:
            # Create access token for user
            access_token = create_access_token(identity=str(user.user_id))
            return {'access_token': access_token}, 200


@ns.route('/signout')
class SignOut(Resource):
    @ns.doc(security='Bearer Auth', parser=auth_header)
    @jwt_required() # add this if you're using JWT for authentication
    def post(self):
        # Delete access token from client-side
        # Return success message
        return {'message': 'Logged out successfully'}, 200


#Creating a namespace for our API
ns2 = api.namespace('usecases', description='The courses namespace provides endpoints for managing courses, including creating, retrieving, updating, and deleting course information.')

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
    }), required=True, description='Label object for the usecase')
})

#Defining endpoints for getting and posting courses
@ns2.route('')
class GetAndPost(Resource):
    def get(self):
        return jsonify(Usecase.objects.order_by('-created_dt'))
    
    @ns2.expect(usecase_model)  # Use the 'expect' decorator to specify the expected payload
    @ns2.doc(security='Bearer Auth', parser=auth_header)
    @jwt_required() # add this if you're using JWT for authentication
    def post(self):
        data=api.payload
        
        # check if usecase name already exists
        if Usecase.objects(usecase_name=data['usecase_name'].upper()):
            return {'message': 'Usecase name already exists'}, 400
        # check if nav_link already exists
        if Usecase.objects(nav_link=data['nav_link']):
            return {'message': 'Nav link already exists'}, 400
        
        ucid_prefix = 'uc'
        max_ucid = Usecase.objects.aggregate({"$group": {"_id": None, "max_ucid": {"$max": "$ucid"}}}).next().get("max_ucid")
        ucid_suffix = str(int(max_ucid[2:]) + 1).zfill(3)
        new_ucid = ucid_prefix + ucid_suffix
        userid=get_jwt_identity()
        usecase=Usecase(usecase_name=data['usecase_name'].upper(),
            heading=data['heading'],
            usecase_desc=data['usecase_desc'],
            disp_order=data['disp_order'],
            nav_link=data['nav_link'],
            created_id=userid,
            created_dt=datetime.utcnow(),
            status=data.get('status', True),
            modify_id=data.get('modify_id', None),
            modify_dt=datetime.utcnow() if data.get('modify_id') else None,
            label=data['label'],
            ucid=new_ucid)  # Use the next ucid value
        usecase.save()
        return jsonify(Usecase.objects(ucid=new_ucid))

#Defining endpoints for getting, updating and deleting courses by ID
@ns2.route('/<idx>')
class GetUpdateDelete(Resource):
    def get(self,idx):
        return jsonify(Usecase.objects(ucid=idx))
    
    @ns2.expect(usecase_model)  # Use the 'expect' decorator to specify the expected payload
    @ns2.doc(security='Bearer Auth', parser=auth_header)
    @jwt_required() # add this if you're using JWT for authentication
    def put(self,idx):
        data=api.payload
        userid=get_jwt_identity()
        data['modify_id'] = userid
        data['modify_dt'] = datetime.utcnow()  # Add modified date to payload
        uc_name=data.get('usecase_name', None)
        navlink=data.get('nav_link', None)
        neg_query = {"ucid": {"$ne": idx}}
        try:
            Usecase.objects(ucid=idx).update(**data)
            return jsonify(Usecase.objects(ucid=idx))
        except NotUniqueError:
            # Ignore the current document being updated
            if Usecase.objects(nav_link=navlink, **neg_query).first():
                return {'message': f'Navigation Link - {navlink} already exists'}, 400
            else:
                return {'message': f'Ucecase name - {uc_name} already exists'}, 400
    
    @ns2.doc(security='Bearer Auth', parser=auth_header)
    @jwt_required() # add this if you're using JWT for authentication
    def delete(self,idx):
        Usecase.objects(ucid=idx).delete()
        return jsonify("Course is deleted!")
    
#Defining endpoints for getting and posting courses
@ns2.route('/ucoptions')
class GetUcids(Resource):
    def get(self):
        ucs=Usecase.objects.exclude('usecase_desc', 'disp_order', 'nav_link', 'created_id', 'created_dt', 'status', 'modify_id', 'modify_dt', 'label')
        ucoptionstore = []
        for uc in ucs:
            ucoptionstore.append({
                'ucid': uc.ucid,
                'heading': uc.heading
            })
        return jsonify(ucoptionstore)

#Creating a namespace for our API
ns3 = api.namespace('picture', description='The courses namespace provides endpoints for managing courses, including creating, retrieving, updating, and deleting course information.')

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

picture_model = ns3.model('Picture', {
    'file': fields.Raw(required=True, description='Image file')
})

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@ns3.route('/profile-picture')
class ProfilePicture(Resource):
    @ns3.expect(picture_model)  # Use the 'expect' decorator to specify the expected payload
    @ns3.doc(security='Bearer Auth', parser=auth_header)
    @jwt_required() # add this if you're using JWT for authentication
    def get(self):
        userid=get_jwt_identity()
        filename = f"{userid}.jpg" # assuming file format is always jpg
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        if os.path.exists(filepath):
            return send_from_directory(app.config['UPLOAD_FOLDER'], filename)
        else:
            return {'message': 'Profile picture not found.'}, 400

    @ns3.expect(picture_model)  # Use the 'expect' decorator to specify the expected payload
    @ns3.doc(security='Bearer Auth', parser=auth_header)
    @jwt_required() # add this if you're using JWT for authentication
    def post(self):
        userid=get_jwt_identity()
        if 'file' not in request.files:
            return {'message': 'No file part in the request.'}, 400
        
        file = request.files['file']
        if file.filename == '':
            return {'message': 'No file selected for uploading.'}, 400

        if file and allowed_file(file.filename):
            filename = secure_filename(f"{userid}.jpg") # assuming file format is always jpg
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            return {'message': 'Profile picture uploaded successfully.'}, 201
        else:
            return {'message': 'Invalid file format. Only JPG, JPEG, PNG, and GIF formats are allowed.'}, 400

    @ns3.expect(picture_model)  # Use the 'expect' decorator to specify the expected payload
    @ns3.doc(security='Bearer Auth', parser=auth_header)
    @jwt_required() # add this if you're using JWT for authentication
    def put(self):
        userid=get_jwt_identity()
        if 'file' not in request.files:
            return {'message': 'No file part in the request.'}, 400

        file = request.files['file']
        if file.filename == '':
            return {'message': 'No file selected for uploading.'}, 400

        if file and allowed_file(file.filename):
            filename = secure_filename(f"{userid}.jpg") # assuming file format is always jpg
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            if os.path.exists(filepath):
                os.remove(filepath)
            file.save(filepath)
            return {'message': 'Profile picture updated successfully.'}, 200
        else:
            return {'message': 'Invalid file format. Only JPG, JPEG, PNG, and GIF formats are allowed.'}, 400
        
#Creating a namespace for our API
ns4 = api.namespace('filesupload', description='The courses namespace provides endpoints for managing courses, including creating, retrieving, updating, and deleting course information.')

ALLOWED_FILE_EXTENSIONS = {'csv', 'txt', 'xls','xlsv','wav','mp3'}

filesuploadmodel = ns4.model('FilesUpload', {
    'file': fields.Raw(required=True, description='Image file')
})

def allowed_file_extension(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_FILE_EXTENSIONS

@ns4.route('')
class UploadFiles(Resource):
    def post(self):
        if 'file' not in request.files:
            return {'message': 'No file part in the request.'}, 400
        
        file = request.files['file']
        if file.filename == '':
            return {'message': 'No file selected for uploading.'}, 400
        
        group = request.form.get('group')  # Retrieve the group name from the request
        ucid = request.form.get('ucid')  # Retrieve the ucid from the request

        if file and allowed_file_extension(file.filename):
            group_directory = os.path.join(app.config['GROUP_FOLDER'], group)
            ucid_directory = os.path.join(group_directory, ucid)
            os.makedirs(ucid_directory, exist_ok=True)  # Create the group directory if it doesn't exist

            filepath = os.path.join(ucid_directory, file.filename)
            file.save(filepath)
            return {'message': 'File uploaded successfully.'}, 200
        else:
            return {'message': 'Invalid file format. Only CSV, XLS, XLSX, TXT, MP3, and WAV formats are allowed.'}, 400
        
@ns4.route('/groups')
class GetGroups(Resource):
    def get(self):
        group_data = []
        group_folder = app.config['GROUP_FOLDER']

        if os.path.isdir(group_folder):
            group_names = os.listdir(group_folder)
            for group_name in group_names:
                group_data.append({'group': group_name})

        return jsonify(group_data)


@ns4.route('/<group>/<ucid>')
class GetFiles(Resource):       
    def get(self,group,ucid):
        group_data = []
        group_folder = app.config['GROUP_FOLDER']
        group_path = os.path.join(group_folder, group, ucid)  # Update the path to include the ucid


        if os.path.isdir(group_path):
            files = []
            file_names = os.listdir(group_path)
            for file_name in file_names:
                file_path = os.path.join(group_path, file_name)
                if os.path.isfile(file_path):
                    file_size = os.path.getsize(file_path)
                    file_url = f"/download/{group}/{ucid}/{file_name}"
                    files.append({
                        'file_name': file_name,
                        'file_size': round(file_size / (1024 * 1024), 2),
                        'file_url': file_url
                    })

            if len(files) == 0:
                return {'message': 'No files available.'}, 404

            group_data.append({'files': files})
        else:
            return {'message': 'Group or UCID not found.'}, 404

        return jsonify(group_data)
    
#Creating a namespace for our API
ns5 = api.namespace('newtableapi', description='The newtableapi namespace provides endpoints for managing newtable data, including creating, retrieving, updating, and deleting newtable data information.')

# Define the expected payload using the 'fields' module
newtable_model = ns5.model('Newtable', {
    'name': fields.String(required=True, description='Name of the newtable model'),
    'age': fields.Integer(required=True, description='Age for the newtable model'),
    'addresstype': fields.String(required=True, description='Address Type for the newtable model')
})

#Defining endpoints for getting and posting newtable data
@ns5.route('')
class GetAndPost(Resource):
    def get(self):
        return jsonify(NewTableModel.objects.order_by('-t_id'))
    
    @ns5.expect(newtable_model)  # Use the 'expect' decorator to specify the expected payload
    def post(self):
        # Get request data from payload
        data=api.payload
        #increment t_id+1 and generate it automatically
        max_tabledata_id = NewTableModel.objects.aggregate({"$group": {"_id": None, "max_tabledata_id": {"$max": "$t_id"}}}).next().get("max_tabledata_id")
        if max_tabledata_id is None:
            max_tabledata_id=0
        tid = max_tabledata_id + 1
        NewTableModel_data=NewTableModel(name=data['name'],age=data['age'],addresstype=data['addresstype'],t_id=tid)
        # Save the new course to the database
        NewTableModel_data.save()
        return {'message': 'Added NewTableModel Data'}, 200

#Defining endpoints for updating newtable data
@ns5.route('/<idx>')
class UpdatePost(Resource): 
    @ns5.expect(newtable_model)  # Use the 'expect' decorator to specify the expected payload
    def put(self,idx):
        data=api.payload
        # Remove the "_id" field from the update data
        if '_id' in data:
            data.pop('_id', None)# Exclude _id field from update   
        NewTableModel.objects(t_id=idx).update(**data)
        return jsonify(NewTableModel.objects(t_id=idx))
    
    def delete(self,idx):
        NewTableModel.objects(t_id=idx).delete()
        return jsonify("NewTable Data is deleted!")

#Creating a namespace for our API
ns6 = api.namespace('remotemode', description='The newtableapi namespace provides endpoints for managing newtable data, including creating, retrieving, updating, and deleting newtable data information.')

# Define the data transfer object (DTO) for the PUT request
remote_val_dto = ns6.model('RemoteValDTO', {
    'remote_val': fields.Integer(required=True, description='Remote Value')
})

@ns6.route('/')
class RemoteResource(Resource):
    def get(self):
        return jsonify(RemoteDocument.objects.all())
    
    @ns6.expect(remote_val_dto)
    def put(self):
        remoteval = api.payload.get('remote_val')
        # Validate the remote_val value
        if remoteval not in [1, 2, 3]:
            return {'message': 'Invalid remote_val value'}, 400
        # Wrap the remote_val in a dictionary
        data={'remote_val':remoteval}
        # Update the document using the `update` method
        RemoteDocument.objects(keycode='REMOTE', pkey='REMOTE').update(**data)
        # Retrieve the updated document
        return jsonify(RemoteDocument.objects(keycode='REMOTE', pkey='REMOTE').first())

        


#Defining the route for the index page
@app.route("/")
@app.route("/index/")
def index():
    return render_template("index.html")

# define an endpoint to verify email
@app.route('/verify_email/<token>', methods=['GET'])
def verify_email(token):
    try:
        email = serializer.loads(token, salt='email-verification', max_age=3600)
        user=users.objects(email=email).first()
        if user:
            user.verified=True
            user.save()
        return jsonify({'message': 'Your account is been Verified now!'}), 200
    except SignatureExpired:
        return jsonify({'message': 'Verification link has expired.'}), 400
    except BadSignature:
        return jsonify({'message': 'Invalid verification link.'}), 400
    
    # define an endpoint to verify email and password
@app.route('/reset_password/<token>', methods=['GET'])
def reset_password(token):
    try:
        data = serializer.loads(token, salt='password-reset', max_age=3600)
        user=users.objects(email=data['email']).first()
        if user:
            user.set_password(data['new_password'])
            user.save()
        return jsonify({'message': 'Your account Password is been Updated now!'}), 200
    except SignatureExpired:
        return jsonify({'message': 'Verification link has expired.'}), 400
    except BadSignature:
        return jsonify({'message': 'Invalid verification link.'}), 400
    
@app.route("/download/<group>/<ucid>/<file_name>")
def download_file(group, ucid, file_name):
    group_directory = os.path.join(app.config['GROUP_FOLDER'], group, ucid)
    file_path = os.path.join(group_directory, file_name)
    return send_file(file_path, as_attachment=True)