from flask import session, redirect, url_for, request, flash
from flask import render_template as flask_render

from app import app, db, login_manager, tags_driver
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash


def render_template(template_name, **kwargs):
	"""Custom render function that passes a set of necessary variables."""

	is_auth = current_user.is_authenticated

	return flask_render(template_name, is_auth=is_auth, **kwargs)


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
	user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
	number_of_likes = db.Column(db.Integer, default=0)
	number_of_comments = db.Column(db.Integer, default=0)

class Like(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
	post_id = db.Column(db.Integer, db.ForeignKey("post.id"))

class Comment(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	username = db.Column(db.String(30))
	user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
	post_id = db.Column(db.Integer, db.ForeignKey("post.id"))
	body = db.Column(db.String(100))


class LoginForm(FlaskForm):
	username = StringField("username", validators=[InputRequired(), Length(min=4, max=15)])
	password = PasswordField("password", validators=[InputRequired(), Length(min=8, max=80)])
	remember = BooleanField("remember me")

class RegisterForm(FlaskForm):
	email = StringField("email", validators=[InputRequired(), Email(message="Invalid email"), Length(max=50)])
	username = StringField("username", validators=[InputRequired(), Length(min=4, max=15)])
	password = PasswordField("password", validators=[InputRequired(), Length(min=8, max=80)])

class PostForm(FlaskForm):
	header = StringField("header", validators=[InputRequired(), Length(min=1, max=30)])
	body = StringField("post", validators=[InputRequired(), Length(min=1, max=1000)])
	tags = StringField("tags", validators=[Length(max=100)])

class FindPostForm(FlaskForm):
	tag = StringField("tag", validators=[Length(max=100)])

"""class ChangeUsername(FlaskForm):
	new_username = StringField("username", validators=[InputRequired(), Length(min=4, max=15)])"""

class ChangePasswordForm(FlaskForm):

	old_password = PasswordField("password", validators=[InputRequired(), Length(min=8, max=80)])
	new_password = PasswordField("password", validators=[InputRequired(), Length(min=8, max=80)])
	confirm_password = PasswordField("password", validators=[InputRequired(), Length(min=8, max=80)])

class CommentForm(FlaskForm):
	body = StringField("post", validators=[InputRequired(), Length(min=1, max=1000)])



@app.route("/")
@app.route("/index")
def index():

	print current_user

	return render_template("index.html")

@app.route("/logout")
@login_required
def logout():
	logout_user()
	return redirect(url_for("posts"))

@app.route("/home")
@login_required
def home():
	return "The current user is" + current_user.username

@app.route("/login", methods=["GET", "POST"])
def login():
	form = LoginForm()

	if form.validate_on_submit():
		user = User.query.filter_by(username=form.username.data).first()
		if user:
			if check_password_hash(user.password, form.password.data):
				login_user(user, remember=form.remember.data)
				return redirect(url_for("posts"))
		return "<h1>Invalid username or password</h1>"
		#return "<h1>" + form.username.data + " " + form.password.data + "</h1>"

	return render_template("login.html", form = form)

@app.route("/signup", methods=["GET", "POST"])
def signup():
	form = RegisterForm()

	if form.validate_on_submit():
		hashed_password = generate_password_hash(form.password.data, method="sha256")
		new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
		db.session.add(new_user)
		db.session.commit()

		return redirect(url_for("login"))
	return render_template("signup.html", form = form)

@app.route("/dashboard")
@login_required
def dashboard():
	return render_template("dashboard.html")

@app.route("/profile", methods=["GET", "POST"])
@app.route("/profile/<int:user_id>", methods=["GET", "POST"])
@login_required
def profile(user_id=None):

	form = ChangePasswordForm()

	if user_id is None:
		user_id = current_user.id

	user = User.query.filter_by(id=user_id).first()

	self_profile = False

	kwargs = {
		"username": user.username,
		"email": user.email,
	}

	print user_id

	if user_id == current_user.id:

		self_profile = True
		success_alert_text = None
		failure_alert_text = None
		password_changed = False

		if form.validate_on_submit():
			if check_password_hash(user.password, form.old_password.data):
				if form.new_password.data == form.confirm_password.data:
					user.password = generate_password_hash(form.new_password.data, method="sha256")
					db.session.add(user)
					db.session.commit()

					password_changed = True
					success_alert_text = "Password was successfully updated"
				else:
					failure_alert_text = "New password and confirmation differ"
			else:
				failure_alert_text = "Old password is incorrect"

		if success_alert_text:
			flash(success_alert_text)
		elif failure_alert_text:
			flash(failure_alert_text)

		kwargs.update({
			"password_changed": password_changed,
			"form": form,
		})

	kwargs.update({"self_profile": self_profile})

	return render_template("profile.html", **kwargs)

@app.route("/writepost", methods=["GET", "POST"])
@login_required
def writepost():
	form = PostForm()

	if form.validate_on_submit():
		post = Post(header=form.header.data, body=form.body.data, username=current_user.username, user_id=current_user.id)
		db.session.add(post)
		db.session.commit()
		tags = form.tags.data.split()
		if tags:
			tags_driver.set_tags(tags, post.id)

		return redirect(url_for("posts"))

	return render_template("writepost.html",form=form)

@app.route("/myposts")
@login_required
def my_posts():

	posts = Post.query.filter_by(user_id=current_user.id)

	return render_template("my_posts.html", username=current_user.username, posts=posts)

@app.route("/allposts")
@login_required
def all_posts():



	posts = Post.query

	return render_template("all_posts.html", posts=posts)

@app.route("/like/<int:post_id>")
@login_required
def like(post_id):

	like = Like(post_id=post_id, user_id=current_user.id)
	db.session.add(like)

	post = Post.query.filter_by(id=post_id).first()
	post.number_of_likes += 1
	db.session.add(post)

	db.session.commit()

	return redirect(url_for("posts"))

@app.route("/post/<int:post_id>", methods=["GET", "POST"])
@login_required
def post(post_id):
	form = CommentForm()

	post = Post.query.filter_by(id=post_id).first()
	tags = ", ".join(sorted(tags_driver.get_tags(post_id)))
	post_comments = Comment.query.filter_by(post_id=post_id)
	
	if form.validate_on_submit():
		comment = Comment(
			username=current_user.username, user_id=current_user.id,
			post_id=post_id, body = form.body.data
		)

		post.number_of_comments += 1
		db.session.add(comment)
		db.session.add(post)
		db.session.commit()

	return render_template(
		"post.html", post=post, tags=tags,
		post_comments=post_comments, form=form,
		username=current_user.username
	)


@app.route("/findposts", methods=["GET", "POST"])
@login_required
def findposts():

	form = FindPostForm()
	posts = []

	if form.validate_on_submit():
		tag = form.tag.data
		post_ids = tags_driver.get_posts(tag)
		posts = Post.query.filter(Post.id.in_(post_ids))

	return render_template("findposts.html", form=form, posts=posts)

@app.route("/posts", methods=["GET", "POST"])
def posts():

	tag = request.form.get("tag")
	if tag is None:
		posts = Post.query
	else:
		post_ids = tags_driver.get_posts(tag)
		posts = Post.query.filter(Post.id.in_(post_ids))

	return render_template("posts.html", posts=posts)


@app.route("/delete_comment/<int:comment_id>", methods=["POST"])
@login_required
def delete_comment(comment_id):

	comment = Comment.query.get(comment_id)

	if comment.user_id == current_user.id:
		Comment.query.filter_by(id=comment_id).delete()
		db.session.commit()

	return redirect(url_for("post", post_id=comment.post_id))


# TODO Implement username change
"""@app.route("/changeusername", methods=["POST"])
@login_required
def changeusername():
	form = ChangeUsername()

	if form.validate_on_submit():
		new_username = form.new_username.data
		login_user(user, remember=form.remember.data)"""
