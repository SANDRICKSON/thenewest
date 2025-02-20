from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_mail import Mail

app=Flask(__name__)
app.config["SECRET_KEY"]="sandrikunaqatamadze"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"


app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'vepkhistyaosaniproject@gmail.com'
app.config['MAIL_PASSWORD'] = 'vymi jkng kwze aphz'
app.config["MAIL_DEFAULT_SENDER"] = 'vepkhistyaosaniproject@gmail.com'

db=SQLAlchemy(app)
login_manager = LoginManager(app)
mail = Mail(app)