import os


class Config:
    SQLALCHEMY_DATABASE_URI = os.getenv('SQLALCHEMY_DATABASE_URI')

    # SECRET_KEY = os.urandom(16).hex()
    SECRET_KEY = os.getenv('SECRET_KEY')
    # WTF_CSRF_SECRET_KEY = os.urandom(16).hex()
    # WTF_CSRF_SECRET_KEY = os.getenv('WTF_CSRF_SECRET_KEY')

    SESSION_COOKIE_DOMAIN = False
    # SESSION_COOKIE_DOMAIN = 'itman7144.pythonanywhere.com'
    # SERVER_NAME = 'itman7144.pythonanywhere.com'

    SQLALCHEMY_TRACK_MODIFICATIONS = False
