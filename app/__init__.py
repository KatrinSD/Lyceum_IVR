from flask import Flask
from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin
from flask_redis import FlaskRedis
from flask_uploads import UploadSet, configure_uploads, IMAGES

app = Flask(__name__)
app.config["REDIS_URL"] = "redis://localhost:6379"
app.config["SECRET_KEY"] = "Thisissupposedtobesecret!"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:////home/ekaterina/Lyceum_IVR/database.db"
#app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:////home/ubuntu/Lyceum_IVR/database.db"
app.config["STATIC_FOLDER"] = None
app.config["PER_PAGE"] = 3
Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
redis = FlaskRedis(app)

photos = UploadSet("photos", IMAGES)
app.config["UPLOADED_PHOTOS_DEST"] = "app/static/img"
configure_uploads(app, photos)

from app.imgindex import ImgIndexDriver
from app.tags import TagsDriver

img_index_driver = ImgIndexDriver(redis)
tags_driver = TagsDriver(redis)

from app import views
from app import utils

app.jinja_env.globals.update(format_datetime=utils.format_datetime)
