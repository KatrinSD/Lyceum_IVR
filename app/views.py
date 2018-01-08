from flask import render_template, session, redirect, url_for

from app import app, db, login_manager, tags_driver
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash


class User(UserMixin, db.Model):
	id = db.Column(db.Integer, primary_key=True)
	username = db.Column(db.String(30), unique=True)
	email = db.Column(db.String(50), unique=True)
	password = db.Column(db.String(80))

@login_manager.user_loader
def load_user(user_id):
	return User.query.get(int(user_id))

class Post(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	header = db.Column(db.String(30))
	body = db.Column(db.String(100))
	username = db.Column(db.String(30))
	user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
	number_of_likes = db.Column(db.Integer, default=0)

class Like(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
	post_id = db.Column(db.Integer, db.ForeignKey('post.id'))

class LoginForm(FlaskForm):
	username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
	password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
	remember = BooleanField('remember me')

class RegisterForm(FlaskForm):
	email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
	username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
	password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])

class PostForm(FlaskForm):
	header = StringField('header', validators=[InputRequired(), Length(min=1, max=30)])
	body = StringField('post', validators=[InputRequired(), Length(min=1, max=1000)])
	tags = StringField('tags', validators=[Length(min=1, max=100)])tags_driver.get_tags(post_id)


@app.route('/')
@app.route('/index')
def index():
    return render_template("index.html")

@app.route('/logout')
@login_required
def logout():
	logout_user()
	return 'You are now logged out!'

@app.route('/home')
@login_required
def home():
	return 'The current user is' + current_user.username

@app.route('/login', methods=['GET', 'POST'])
def login():
	form = LoginForm()

	if form.validate_on_submit():
		user = User.query.filter_by(username=form.username.data).first()
		if user:
			if check_password_hash(user.password, form.password.data):
				login_user(user, remember=form.remember.data)
				return redirect(url_for('dashboard'))
		return '<h1>Invalid username or password</h1>'
		#return '<h1>' + form.username.data + ' ' + form.password.data + '</h1>'

	return render_template("login.html", form = form)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
	form = RegisterForm()

	if form.validate_on_submit():
		hashed_password = generate_password_hash(form.password.data, method='sha256')
		new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
		db.session.add(new_user)
		db.session.commit()

		return '<h1>New user has been created!</h1>'
		#return '<h1>' + form.username.data + ' ' + form.email.data + ' ' + form.password.data + '</h1>'

	return render_template("signup.html", form = form)

@app.route('/dashboard')
@login_required
def dashboard():
	return render_template("dashboard.html")

@app.route('/profile')
@login_required
def profile():

	kwargs = {
		"username": current_user.username,
		"email": current_user.email,
	}

	return render_template("profile.html", **kwargs)

@app.route('/writepost', methods=['GET', 'POST'])
@login_required
def writepost():
	form = PostForm()

	if form.validate_on_submit():
		post = Post(header=form.header.data, body=form.body.data, username=current_user.username, user_id=current_user.id)
		db.session.add(post)
		db.session.commit()
		tags = form.tags.data.split()
		tags_driver.set_tags(tags, post.id)

		return '<h1>New post has been created!</h1>'

	return render_template("writepost.html",form=form)

@app.route('/myposts')
@login_required
def my_posts():

	posts = Post.query.filter_by(user_id=current_user.id)

	return render_template("my_posts.html", username=current_user.username, posts=posts)

@app.route('/allposts')
@login_required
def all_posts():

	posts = Post.query

	return render_template("all_posts.html", posts=posts)

@app.route('/like/<int:post_id>')
@login_required
def like(post_id):

	like = Like(post_id=post_id, user_id=current_user.id)
	db.session.add(like)

	post = Post.query.filter_by(id=post_id).first()
	post.number_of_likes += 1
	db.session.add(post)

	db.session.commit()

	return redirect(url_for('all_posts'))

@app.route('/post/<int:post_id>')
@login_required
def post(post_id):
	post = Post.query.filter_by(id=post_id).first()
	tags = ", ".join(sorted(tags_driver.get_tags(post_id)))

	return render_template("post.html", post=post, tags=tags)
