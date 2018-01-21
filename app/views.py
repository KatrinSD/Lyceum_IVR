import datetime
import uuid

from flask import session, redirect, url_for, request, flash
from flask import render_template as flask_render
from flask_paginate import Pagination, get_page_args
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, PasswordField, BooleanField, FileField, TextAreaField
from wtforms.validators import InputRequired, Email, Length
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.exceptions import HTTPException

from app import app, db, login_manager, tags_driver, photos, img_index_driver


def render_template(template_name, **kwargs):
	"""Custom render function that passes a set of necessary variables."""

	is_auth = current_user.is_authenticated

	drafts_count = 0
	if is_auth:
		drafts_count = Post.query.filter_by(
			user_id=current_user.id,
			is_draft=True,
		).count()

	return flask_render(template_name,
		is_auth=is_auth, drafts_count=drafts_count,
		**kwargs
	)


def render_http_error(error_code, msg=None):
	"""Returns html for requested http error."""

	template_name = ".".join([str(error_code), "html"])

	return render_template(template_name, error_msg=msg)


def render_401_unauthorized(entity_name):
	"""Returns html for Unauthorized error."""

	return render_http_error(401)


def render_403_forbidden():
	"""Returns html for Forbidden error."""

	return render_http_error(403)


def render_404_not_found(entity_name):
	"""Returns html for Not Found error for entity."""

	msg = "Requested {0} not found".format(entity_name)

	return render_http_error(404, msg)


def render_500_internal_server_error():
	"""Returns html for Internal Server Error error."""

	return render_http_error(500)


TEMPLATED_HTTP_ERRORS = (
	401,
	403,
	404,
)
"""HTTP errors that have custom templates."""


@app.errorhandler(Exception)
def handle_error(e):
	"""Handles exceptions and returns most presice http error possible."""

	code = 500
	if isinstance(e, HTTPException) and code not in TEMPLATED_HTTP_ERRORS:
		code = e.code

	print "Exception raised: {0}".format(e)

	return render_http_error(code)


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
	number_of_photos = db.Column(db.Integer, default=0)
	is_draft = db.Column(db.Boolean)
	date_created = db.Column(db.DateTime, index=True, default=datetime.datetime.utcnow())

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
	date_created = db.Column(db.DateTime, index=True, default=datetime.datetime.utcnow())

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
	body = TextAreaField("body", validators=[InputRequired(), Length(min=1, max=1000)])
	tags = StringField("tags", validators=[Length(max=100)])

#class UploadPhotosForm(FlaskForm):
	#photos = FileField("photos", validators=[(FileAllowed(photos, "Images only"))])
#	photos = FileField("photos")

class FindPostForm(FlaskForm):
	tag = StringField("tag", validators=[Length(max=100)])

"""class ChangeUsername(FlaskForm):
	new_username = StringField("username", validators=[InputRequired(), Length(min=4, max=15)])"""

class ChangePasswordForm(FlaskForm):

	old_password = PasswordField("password", validators=[InputRequired(), Length(min=8, max=80)])
	new_password = PasswordField("password", validators=[InputRequired(), Length(min=8, max=80)])
	confirm_password = PasswordField("password", validators=[InputRequired(), Length(min=8, max=80)])

class CommentForm(FlaskForm):
	body = TextAreaField("body", validators=[InputRequired(), Length(min=1, max=1000)])



@app.route("/")
@app.route("/index")
def index():

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

	if user is None:
		return render_404_not_found("user")

	self_profile = False

	kwargs = {
		"username": user.username,
		"email": user.email,
	}

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
		post = Post(
			header=form.header.data,
			body=form.body.data,
			username=current_user.username,
			user_id=current_user.id,
			is_draft=True,
		)
		db.session.add(post)
		db.session.commit()
		tags = form.tags.data.split()
		if tags:
			tags_driver.set_tags(tags, post.id)

		return redirect(url_for("upload_photos", post_id=post.id))

	return render_template("writepost.html",form=form)

@app.route("/uploadphotos/<int:post_id>", methods=["GET", "POST"])
@login_required
def upload_photos(post_id):

	post = Post.query.filter_by(
		user_id=current_user.id,
		id=post_id,
		is_draft=True
	).first()

	# TODO: add raise here
	if post is None:
		return redirect(url_for("posts"))

	image_ids = []

	if request.method == "POST":
		files = request.files.getlist("photos")
		if len(files) and files[0].filename:

			for image in request.files.getlist("photos"):
				image_id = str(uuid.uuid4())
				image_id = ".".join([image_id, image.filename.rsplit(".", 1)[1]])
				image.filename = image_id
				photos.save(image)
				image_id = "/".join(["img", image_id])
				image_ids.append(image_id)

		img_index_driver.set_image_ids(image_ids, post.id)
		post.number_of_photos = len(image_ids)
		post.is_draft = False
		db.session.add(post)
		db.session.commit()

		return redirect(url_for("posts"))

	return render_template("uploadphotos.html", post_id=post_id)


@app.route("/myposts")
@login_required
def my_posts():

	posts_count = Post.query.filter_by(user_id=current_user.id).count()
	page, per_page, offset = get_page_args("page", "per_page")
	posts = Post.query.filter_by(user_id=current_user.id).order_by(Post.date_created.desc()).offset(offset).limit(per_page)
	pagination = Pagination(page=page, total=posts_count, per_page=per_page, record_name="posts", css_framework="bootstrap3")

	return render_template("my_posts.html", username=current_user.username, posts=posts, pagination=pagination)

@app.route("/like/<int:post_id>")
@login_required
def like(post_id):

	like_change = 1

	if Like.query.filter_by(post_id=post_id, user_id=current_user.id).first() is not None:
		Like.query.filter_by(post_id=post_id, user_id=current_user.id).delete()
		like_change = -1
	else:
		like = Like(post_id=post_id, user_id=current_user.id)
		db.session.add(like)

	post = Post.query.filter_by(id=post_id).first()
	post.number_of_likes += like_change
	db.session.add(post)

	db.session.commit()

	return redirect(url_for("posts"))

@app.route("/post/<int:post_id>", methods=["GET", "POST"])
@login_required
def post(post_id):
	form = CommentForm()

	post = Post.query.filter_by(id=post_id).first()

	if post is None:
		return render_404_not_found("post")

	tags = ", ".join(sorted(tags_driver.get_tags(post_id)))

	post_comments_count = Comment.query.filter_by(post_id=post_id).count()
	page, per_page, offset = get_page_args("page", "per_page")
	post_comments = Comment.query.filter_by(post_id=post_id).order_by(Comment.date_created.desc()).offset(offset).limit(per_page)
	pagination = Pagination(page=page, total=post_comments_count, per_page=per_page, record_name="comments", css_framework="bootstrap3")

	post_image_ids = img_index_driver.get_image_ids(post_id)

	if form.validate_on_submit():
		comment = Comment(
			username=current_user.username, user_id=current_user.id,
			post_id=post_id, body = form.body.data, date_created=datetime.datetime.utcnow()
		)

		post.number_of_comments += 1
		db.session.add(comment)
		db.session.add(post)
		db.session.commit()

	return render_template(
		"post.html", post=post, tags=tags,
		post_comments=post_comments, form=form,
		username=current_user.username,
		post_image_ids=post_image_ids,
		pagination=pagination,
	)


@app.route("/posts", methods=["GET", "POST"])
def posts():

	tag = request.form.get("tag")
	print "TAG: [{0}]".format(tag)
	page, per_page, offset = get_page_args("page", "per_page")
	pagination = None
	
	if tag:
		post_ids = tags_driver.get_posts(tag)
		posts = Post.query.filter(Post.id.in_(post_ids)).order_by(Post.date_created.desc())
	else:
		posts_count = Post.query.count()
		posts = Post.query.order_by(Post.date_created.desc()).offset(offset).limit(per_page)
		pagination = Pagination(page=page, total=posts_count, per_page=per_page, record_name="posts", css_framework="bootstrap3")

	return render_template("posts.html", posts=posts, search=bool(tag), pagination=pagination)


@app.route("/delete_comment/<int:comment_id>", methods=["POST"])
@login_required
def delete_comment(comment_id):

	comment = Comment.query.get(comment_id)

	if comment is None:
		return render_404_not_found("comment")

	if comment.user_id == current_user.id:
		Comment.query.filter_by(id=comment_id).delete()
		db.session.commit()
	else:
		return render_403_forbidden()

	return redirect(url_for("post", post_id=comment.post_id))


@app.route("/delete_post/<int:post_id>", methods=["POST"])
@login_required
def delete_post(post_id):

	post = Post.query.get(post_id)
	if post is None:
		return render_404_not_found("post")

	if post.user_id != current_user.id:
		return render_403_forbidden()

	Post.query.filter_by(id=post_id).delete()
	Comment.query.filter_by(post_id=post_id).delete()
	Like.query.filter_by(post_id=post_id).delete()

	db.session.commit()

	tags = tags_driver.get_tags(post_id)

	for tag in tags:
		tags_driver.remove_post_id_from_tags(tag, post_id)

	tags_driver.delete_post_id(post_id)

	return redirect(url_for("my_posts"))


@app.route("/drafts", methods=["GET"])
@login_required
def drafts():

	drafts = Post.query.filter_by(user_id=current_user.id, is_draft=True)

	return render_template("drafts.html", drafts=drafts)


@app.route("/delete_draft/<int:post_id>", methods=["POST"])
@login_required
def delete_draft(post_id):

	draft = Post.query.get(post_id)
	if draft is None:
		return render_404_not_found("draft")

	if draft.user_id == current_user.id:
		if draft.is_draft:
			Post.query.filter_by(id=post_id).delete()
			db.session.commit()

			tags = tags_driver.get_tags(post_id)

			for tag in tags:
				tags_driver.remove_post_id_from_tags(tag, post_id)

			tags_driver.delete_post_id(post_id)
	else:
		return render_403_forbidden()

	return redirect(url_for("drafts"))
