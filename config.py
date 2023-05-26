import os


class Config:
    SQLALCHEMY_DATABASE_URI = os.getenv('SQLALCHEMY_DATABASE_URI')

    # SECRET_KEY = os.urandom(16).hex()
    SECRET_KEY = os.getenv('SECRET_KEY')
    WTF_CSRF_TIME_LIMIT = 5
    # WTF_CSRF_SECRET_KEY = os.urandom(16).hex()
    # WTF_CSRF_SECRET_KEY = os.getenv('WTF_CSRF_SECRET_KEY')
    # WTF_CSRF_CHECK_DEFAULT = True

    SESSION_COOKIE_DOMAIN = False
    # SESSION_COOKIE_DOMAIN = 'itman7144.pythonanywhere.com'
    SERVER_NAME = 'itman7144.pythonanywhere.com'

    # SESSION_COOKIE_DOMAIN = None
    # SERVER_NAME = None

    SQLALCHEMY_TRACK_MODIFICATIONS = False
