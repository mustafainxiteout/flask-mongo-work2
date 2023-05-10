import os
import secrets
from datetime import timedelta

class Config(object):
    # A secret key is used to keep the client-side sessions secure. Here, the key is taken from an environment variable
    # named 'SECRET_KEY'. If it doesn't exist, a default string 'secret_string' is used as the secret key.
    SECRET_KEY=os.environ.get('SECRET_KEY') or b'\x9fJ\x81\x1d\xeb\xdb\xc4\x0cSaTX\xc8i\xbb#'

    JWT_SECRET_KEY = secrets.token_urlsafe(32)
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(days=7)

    basedir = os.path.abspath(os.path.dirname(__file__))
    UPLOAD_FOLDER = os.path.join(basedir, 'application/static', 'uploads')

    GROUP_FOLDER = os.path.join(basedir, 'application/static', 'groups')

    # MongoDB settings are defined as a list of dictionaries, with each dictionary representing a MongoDB instance.
    # Here, a single MongoDB instance is defined with a database name 'UTA_Enrollment', host address '127.0.0.1',
    # port number '27017', and an alias 'default'.
    MONGODB_SETTINGS=[ {"db": "UTA_Enrollment","host": "127.0.0.1","port": 27017,"alias": "default"}]

    # configure Flask Mail
    MAIL_SERVER = 'sandbox.smtp.mailtrap.io'
    MAIL_PORT = 2525
    MAIL_USE_TLS = True
    MAIL_USE_SSL = False
    MAIL_USERNAME = '788a6c95ec689c'
    MAIL_PASSWORD = 'd2555919896f13'
    MAIL_DEFAULT_SENDER= 'from@example.com'