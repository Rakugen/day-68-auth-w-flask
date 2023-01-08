from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

app = Flask(__name__)

app.config['SECRET_KEY'] = 'shibasarecool'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)


##CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))

# Line below only required once, when creating DB.
# with app.app_context():
#     db.create_all()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def home():
    return render_template("index.html")


@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == "POST":
        # Checks if user already exists
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
    return render_template("register.html")


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

        # Password inccorect
        elif not check_password_hash(user.password, password):
            flash("Incorrect password, please try again")
            return redirect(url_for("login"))

        # Correctly logged in
        else:
            login_user(user)
            flash("Successfully logged in")
            return redirect(url_for("secrets"))

    return render_template("login.html")


@app.route('/secrets')
@login_required
def secrets():
    print(current_user.name)
    return render_template("secrets.html", name=current_user.name)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for("home"))


@app.route('/download')
@login_required
def download():
    return send_from_directory('static', path='files/cheat_sheet.pdf')


if __name__ == "__main__":
    app.run(debug=True)
