from models import User
from extensions import app, db

with app.app_context():
    new_user = User()
    db.create_all()