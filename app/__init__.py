from flask import Flask
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
# csrf = CSRFProtect(app)
app.config.from_object('config.Config')
# app.config["SQLALCHEMY_DATABASE_URI"] = 'sqlite:///flask-site-db.sqlite3'
# app.config["SECRET_KEY"] = 'HKJFghedfkh784yuHKJFh430789/L:F34kl;3rP&y4809rywahrf'
# app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# images_folder = os.path.join('static', 'images')
# , static_url_path='/static'
# app.config['UPLOAD_FOLDER'] = images_folder

db = SQLAlchemy(app)
from .views import *
from .models import *

app.app_context().push()
db.create_all()
manager = LoginManager(app)


@manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)
