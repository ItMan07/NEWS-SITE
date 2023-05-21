from flask import render_template, redirect, url_for
from flask_login import login_required, login_user, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

from . import app, db
from .forms import *
from .models import *


# TODO:
#  1. БД: автор статьи
#  2. БД: проверять админку
#  3. БД: страница профиля
#  4. доделать футер
#  5. доделать редактирование (нет дефолтного значения категории и текста)

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
    data = {
        'news': News.query.get(news_id),
        'categories': Category.query.all(),
        'is_auth': True if current_user.is_authenticated else False,
        'show_categories': True
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

    return render_template('register.html', form=form, data=data)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    data = {
        'categories': Category.query.all(),
        'is_auth': True if current_user.is_authenticated else False,
        'show_categories': False
    }

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            print('login user')
            return redirect(url_for('index'))
        else:
            # flash('Login or password is not correct')
            print('Login or password is not correct')
            pass

    return render_template('login.html', form=form, data=data)


@app.route('/profile/<int:user_id>', methods=['GET', 'POST'])
def profile(user_id):
    data = {
        'categories': Category.query.all(),
        'is_auth': True if current_user.is_authenticated else False,
        'show_categories': False
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
