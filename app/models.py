from datetime import datetime

from flask_login import UserMixin

from . import db


class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    news = db.relationship('News', back_populates='category')


class News(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    text = db.Column(db.Text, nullable=False)
    create_date = db.Column(db.DateTime, default=datetime.utcnow)

    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=True)
    category = db.relationship('Category', back_populates='news')


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(329), nullable=True, default=None)
    password = db.Column(db.String(255), nullable=False)
    # datetime.utcnow().strftime('%d.%m.%Y %H:%M')
    reg_date = db.Column(db.DateTime, default=datetime.utcnow)
    admin = db.Column(db.Boolean, nullable=False, default=False)
