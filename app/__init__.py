from flask import Flask
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy

from .models import *
from .views import *

# from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
# csrf = CSRFProtect(app)
# csrf.init_app(app)
app.config.from_object('config.Config')

db = SQLAlchemy(app)
app.app_context().push()
db.create_all()
manager = LoginManager(app)


@manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)
