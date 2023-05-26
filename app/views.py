import os
import secrets

from flask import render_template, redirect, url_for, session, g, flash, abort, request
from flask_login import login_required, login_user, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

from . import app, db
from .forms import *
from .models import *


# TODO:
#  1. БД: автор статьи
#  2. БД: проверять админка
#  3. БД: страница профиля
#  4. доделать футер
#  5. доделать редактирование (нет дефолтного значения категории и текста)

# @app.before_request
# def fix_missing_csrf_token():
#     if app.config['WTF_CSRF_FIELD_NAME'] not in session:
#         if app.config['WTF_CSRF_FIELD_NAME'] in g:
#             g.pop(app.config['WTF_CSRF_FIELD_NAME'])
@app.before_request
def csrf_protect():
    if request.method == "POST":
        csrf_token = session.pop("_csrf_token", None)
        if not csrf_token or csrf_token != request.form.get("_csrf_token"):
            abort(403)


@app.route('/')
def index():
    data = {
        'news': News.query.order_by(News.id.desc()).all(),
        'categories': Category.query.all(),
        'is_auth': True if current_user.is_authenticated else False,
        'show_categories': True
    }
    return render_template('index.html', data=data)


@app.route('/about')
def about():
    data = {
        'categories': Category.query.all(),
        'is_auth': True if current_user.is_authenticated else False,
        'show_categories': False
    }
    return render_template('about.html', data=data)


@app.route('/news/<int:news_id>')
def news_detail(news_id):
    # is_admin, is_auth = False, False
    # if current_user.is_anonymous:
    #     is_admin, is_auth = False, False
    # if :
    #     user = User.query.get(current_user.id)
    # is_admin = True if user.admin == 1 else False
    # is_author = True if News.query.get(news_id).author_id == user_id else False

    data = {
        'news': News.query.get(news_id),
        'categories': Category.query.all(),
        'is_auth': True if current_user.is_authenticated else False,
        'show_categories': True,
        # 'is_author': is_author,
        'is_admin': True if current_user.is_authenticated and
                            User.query.get(current_user.id).admin else False
    }
    return render_template('news_detail.html', data=data)


@app.route('/create_news', methods=['POST', 'GET'])
@login_required
def create_news():
    form = NewsForm()
    data = {
        'categories': Category.query.all(),
        'is_auth': True if current_user.is_authenticated else False,
        'show_categories': False
    }

    if form.validate_on_submit():
        news = News()
        news.title = form.title.data
        news.text = form.text.data
        news.category_id = form.category.data
        db.session.add(news)
        db.session.commit()
        return redirect(url_for('index'))
    return render_template('create_news.html', form=form, data=data)


@app.route('/create_news_hidden', methods=['POST', 'GET'])
# @login_required
def create_news_hidden():
    form = NewsForm()
    data = {
        'categories': Category.query.all(),
        'is_auth': True if current_user.is_authenticated else False,
        'show_categories': False
    }

    if form.validate_on_submit():
        news = News()
        news.title = form.title.data
        news.text = form.text.data
        news.category_id = form.category.data
        db.session.add(news)
        db.session.commit()
        return redirect(url_for('index'))
    return render_template('create_news.html', form=form, data=data)


@app.route('/category/<int:id>')
def news_in_category(id):
    data = {
        'categories': Category.query.all(),
        'category': Category.query.get(id),
        'is_auth': True if current_user.is_authenticated else False,
        'news': Category.query.get(id).news,
        'category_name': Category.query.get(id).title,
        'show_categories': True
    }
    return render_template('category.html', data=data)


@app.route('/news/<int:news_id>/edit', methods=['GET', 'POST'])
@login_required
def news_edit(news_id):
    form = NewsForm()
    news = News.query.get(news_id)
    # title.default = 123
    # NewsForm.title.default = '123'
    # form = form.title(default='123')
    data = {
        'categories': Category.query.all(),
        'is_auth': True if current_user.is_authenticated else False,
        'show_categories': True,
        'def_values': [news.title, news.text, Category.query.get(news.category_id).title]
    }
    print('DATA:', data['def_values'][2], data['def_values'][1])
    # print(db.session.get(news_id).title, db.session.get(news_id).text, db.session.get(news_id).category_id)

    if form.validate_on_submit():
        news.title = form.title.data
        news.text = form.text.data
        news.category_id = form.category.data
        db.session.add(news)
        db.session.commit()
        return redirect(url_for('index'))
    return render_template('edit_news.html', form=form, data=data)


@app.route('/news/<int:news_id>/delete')
@login_required
def news_delete(news_id):
    news = News.query.get(news_id)
    db.session.delete(news)
    db.session.commit()
    return redirect(url_for('index'))


@app.route('/create_category', methods=['POST', 'GET'])
@login_required
def create_category():
    form = CategoriesForm()
    data = {
        'categories': Category.query.all(),
        'is_auth': True if current_user.is_authenticated else False,
        'show_categories': True
    }

    if form.validate_on_submit():
        category = Category()
        category.title = form.title.data
        db.session.add(category)
        db.session.commit()
        return redirect(url_for('index'))
    return render_template('create_category.html', form=form, data=data)


@app.route('/register', methods=['POST', 'GET'])
def register():
    form = RegisterForm()
    data = {
        'categories': Category.query.all(),
        'is_auth': True if current_user.is_authenticated else False,
        'show_categories': False
    }

    if form.validate_on_submit():
        user = User()
        user.username = form.username.data
        user.password = generate_password_hash(form.password.data)
        db.session.add(user)
        db.session.commit()
        print('register user')
        return redirect(url_for('login'))

    return render_template('register.html', form=form, data=data, csrf_token=session["_csrf_token"])


# Для создания уникального CSRF-токена для каждого посетителя сайта в Flask можно использовать модуль
# secrets для генерации случайного токена при каждом запросе.
#
# Вот пример кода, который генерирует уникальный CSRF-токен для каждого запроса в Flask:

# from flask import Flask, session
# import secrets
#
# app = Flask(__name__)
#
# @app.before_request
# def csrf_protect():
#     if request.method == "POST":
#         csrf_token = session.pop("_csrf_token", None)
#         if not csrf_token or csrf_token != request.form.get("_csrf_token"):
#             abort(403)
#
# @app.route("/")
# def index():
#     session["_csrf_token"] = secrets.token_hex(16)
#     return render_template("index.html", csrf_token=session["_csrf_token"])
#
# В этом примере мы используем декоратор before_request, чтобы проверить CSRF-токен при каждом POST-запросе.
# Если CSRF-токен не совпадает с токеном, сохраненным в сессии, мы вызываем ошибку 403.
#
# В функции маршрутизации index() мы генерируем уникальный CSRF-токен с помощью функции secrets.token_hex(16) и
# сохраняем его в сессии. Затем мы возвращаем шаблон index.html с CSRF-токеном в качестве аргумента.
#
# В шаблоне index.html мы можем использовать CSRF-токен в форме следующим образом:
#
# <form method="post">
#     <input type="hidden" name="_csrf_token" value="{{ csrf_token }}">
#     <!-- остальные поля формы -->
# </form>
#
# Здесь мы добавляем скрытое поле _csrf_token в форму и устанавливаем его значение равным CSRF-токену,
# переданному из Flask-приложения. Таким образом, при каждом запросе генерируется
# новый уникальный CSRF-токен, который используется для защиты от CSRF-атак.


@app.route('/login', methods=['POST', 'GET'])
def login():
    # app.config['SECRET_KEY'] = os.urandom(16).hex()
    # session['CSRF_TOKEN'] = os.urandom(16).hex()
    session["_csrf_token"] = secrets.token_hex(16)
    form = LoginForm(csrf_protect=session["_csrf_token"])

    data = {
        'categories': Category.query.all(),
        'is_auth': True if current_user.is_authenticated else False,
        'show_categories': False
    }

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        remember = form.remember_me.data
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user, remember=remember)
            print('login user')
            return redirect(url_for('index'))
        else:
            # flash('Login or password is not correct')
            print('Login or password is not correct')
            pass

    return render_template('login.html', form=form, data=data)


# @app.route('/login', methods=['GET', 'POST'])
# def login():
#     form = LoginForm()
#     if form.validate_on_submit():
#         flash('Login requested for OpenID="' + form.openid.data + '", remember_me=' + str(form.remember_me.data))
#         return redirect('/index')
#     return render_template('login.html',
#                            title='Sign In',
#                            form=form,
#                            providers=app.config['OPENID_PROVIDERS'])


@app.route('/profile/<int:user_id>', methods=['POST', 'GET'])
@login_required
def profile(user_id):
    user_data = []
    if current_user.is_authenticated:
        user = User.query.get(current_user.id)
        user_data = [user.username, user.email, user.reg_date, user.admin]
    data = {
        'categories': Category.query.all(),
        'is_auth': True if current_user.is_authenticated else False,
        'show_categories': False,
        'user_data': user_data
    }
    return render_template('profile.html', data=data)


@app.errorhandler(404)
def error_404(e):
    data = {
        'is_auth': True if current_user.is_authenticated else False,
        'show_categories': False,
        'error': 'Упс. Страница не найдена :('
    }
    return render_template('errors.html', data=data)


@app.errorhandler(401)
def error_401(e):
    return redirect(url_for('login'))


@login_required
@app.route('/logout', methods=['GET', 'POST'])
def logout():
    logout_user()
    print('logout user')
    return redirect(url_for('index'))
