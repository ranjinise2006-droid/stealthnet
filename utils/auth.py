from flask_login import UserMixin

# Demo user (can replace with DB later)
USERS = {
    "admin": "classified123"
}

class User(UserMixin):
    def __init__(self, username):
        self.id = username

def authenticate_user(username, password):
    return USERS.get(username) == password
