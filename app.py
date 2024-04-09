from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase,Mapped,mapped_column
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

class Base(DeclarativeBase):
  pass
db = SQLAlchemy(model_class=Base)
# create the app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'any-secret-key-you-choose'
# configure the SQLite database, relative to the app instance folder
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"
# initialize the app with the extension
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

##CREATE TABLE IN DB
class User(UserMixin,db.Model):
    id:Mapped[int] = mapped_column(primary_key=True)
    email:Mapped[str] =mapped_column(unique=True)
    password:Mapped[str] =mapped_column(nullable=False)
    name: Mapped[str] = mapped_column(nullable=False)
# Two Lines below only required once, when creating DB.
# with app.app_context():
#     db.create_all()

@app.route('/')
def home():
    return render_template("index.html",logged_in=current_user.is_authenticated)


@app.route('/register',methods=["GET","POST"])
def register():
    if request.method == "POST":
        # User already Exists
        if User.query.filter_by(email = request.form.get('email')).first():
            flash("You've already signed up with this mail, Log in instead")
            return redirect(url_for('login'))
        hash_and_salt_password = generate_password_hash(
            request.form.get("password"),
            method="pbkdf2:sha256",
            salt_length=8
        )
        new_user = User(
            email = request.form.get('email'),
            password=hash_and_salt_password,
            name=request.form.get('name'),
        )
        db.session.add(new_user)
        db.session.commit()
        load_user(new_user)
        return  redirect(url_for('secrets'))
    return render_template("register.html",logged_in=current_user.is_authenticated)


@app.route('/login',methods=["GET","POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        #Find user by Email
        user = User.query.filter_by(email=email).first()
        #email does not exists
        if not user:
            flash("This email not exists, Please Try Again!")
        # Check the Password
        elif not check_password_hash(user.password,password):
            flash("Password Incorrect, Please Try Again!")
            return redirect(url_for('login'))
        else:
            login_user(user)
            return redirect(url_for('secrets'))

    return render_template("login.html",logged_in=current_user.is_authenticated)


@app.route('/secrets')
@login_required
def secrets():
    print(current_user.name)
    return render_template("secrets.html",name=current_user.name,logged_in=True)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/download')
@login_required
def download():
    return send_from_directory(directory='static',path='files/secrets.pdf')


