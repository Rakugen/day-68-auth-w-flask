# A practice website that lets you login/logout, authenticate a user, load and serve a download link(pdf) automatically,
# as well as show flash(error) messages when unable to login correctly.
# Project utilizes concepts of Flask, Jinja templating, SQL databases via SQLAlchemy, authentication with
# hashing+salting security via werkzeug, login management functionality built-into flask with flask_login.

from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

app = Flask(__name__)

# Standard Flask and SQLalchemy setup with the new addition of LoginManager that will allow us to handle how the app
# interacts with user logins
app.config['SECRET_KEY'] = 'shibasarecool'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)


# Standard DB/Table creation w/ addition of UserMixin that inherits functionality for Flask_Login
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))

# Line below only required once, when creating DB.
# with app.app_context():
#     db.create_all()

# user_loader needed for LoginManager to handle users
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Home route with logged_in used as managing which navbar links show on top
@app.route('/')
def home():
    return render_template("index.html", logged_in=current_user.is_authenticated)

# Register route that will create a new user into db via html form.
# werkzeug.security is used to generate a hashed password
@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == "POST":
        # Checks if user already exists in database
        if User.query.filter_by(email=request.form.get('email')).first():
            flash("You've already signed up with that email. Please login")
            return redirect(url_for("login"))
        hashed_pw = generate_password_hash(
            request.form.get("password"),
            method="pbkdf2:sha256",
            salt_length=8
        )
        new_user = User(
            email=request.form.get('email'),
            password=hashed_pw,
            name=request.form.get('name')
        )
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for("secrets", user_id=new_user.id))
    return render_template("register.html", logged_in=current_user.is_authenticated)

# Login route that checks credentials and attempts to log-in a user. Flash messages are used to display
# errors in validating credentials. login_user() is used here from LoginManager
@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        user = User.query.filter_by(email=email).first()
        # User doesn't exist
        if not user:
            flash("That email does not exist, please try again")
            return redirect(url_for("login"))
        # Incorrect Password
        elif not check_password_hash(user.password, password):
            flash("Incorrect password, please try again")
            return redirect(url_for("login"))
        # Correctly logged in
        else:
            login_user(user)
            flash("Successfully logged in")
            return redirect(url_for("secrets"))

    return render_template("login.html", logged_in=current_user.is_authenticated)

# Secrets route that will serve the pdf download link w/ addition of @login_required decorator that enforces
# the need for a logged-in user
@app.route('/secrets')
@login_required
def secrets():
    print(current_user.name)
    return render_template("secrets.html", name=current_user.name, logged_in=True)

# Logout route that uses logout_user() from LoginManager
@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for("home"))

# Download route that will load the pdf onto the page also w/ enforcement of logged in user
@app.route('/download')
@login_required
def download():
    return send_from_directory('static', path='files/cheat_sheet.pdf')


if __name__ == "__main__":
    app.run(debug=True)
