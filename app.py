from flask import Flask, render_template, request, url_for, session, redirect, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import *#form creation
from wtforms.validators import *
from flask_bcrypt import Bcrypt
from datetime import datetime, timedelta
import datetime


# ******CONFIG******

app = Flask(__name__)
app.debug = True
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.sqlite'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
app.config['SECRET_KEY'] ='secretkey'


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))



class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False, unique=True)
    password = db.Column(db.String(50), nullable=False)
    # patients = db.relationship('Patient', backref='user')
    name = db.Column(db.String(50), nullable=False)
    address = db.Column(db.String(80), nullable=False)
    city = db.Column(db.String(30), nullable=False)
    dob = db.Column(db.Date, nullable=False)
    gender = db.Column(db.String(10), nullable=False)
    mobile = db.Column(db.Integer)

class Doctor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    username = db.Column(db.String(50), nullable=False, unique=True)
    password = db.Column(db.String(50), nullable=False)
    speciality = db.Column(db.String(50), nullable=False)

class Appointment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    # user = db.relationship('User', backref='user')
    slot = db.Column(db.String(50), nullable=False)
    date = db.Column(db.Date, nullable=False)


# ****** FORMS *******

class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "User Name"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField("Register")
    gender = RadioField('Gender', choices=[('Male'),('Female'),('Other')])
    fullname = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Full Name"})
    address = StringField(validators=[InputRequired(), Length(min=4, max=100)], render_kw={"placeholder": "Address"})
    mobile = StringField(validators=[InputRequired(), Length(min=10, max=12)], render_kw={"placeholder": "Mobile No."})
    city = StringField(validators=[InputRequired(), Length(min=4, max=30)], render_kw={"placeholder": "City"})
    dob = DateField(validators=[InputRequired()],render_kw={"placeholder": "Date of Birth"})

    # confirm = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Confirm Password"})
    def validate_username(self, username):
        existing_user_username = User.query.filter_by(username=username.data).first()
        if existing_user_username:
            raise ValidationError("Username already exists.")
        
class AppointmentForm(FlaskForm):
    slot = SelectField("Appointment Slot", choices=[("morning", "Morning (9am-12pm)"), ("afternoon", "Afternoon (1pm-4pm)"), ("evening", "Evening (5pm-8pm)")])
    date = DateField("Appointment Date")
    submit = SubmitField("Book Appointment")

# ******** ROUTES ********
# REGISTRATION
@app.route("/register", methods=['GET','POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password, name=form.fullname.data, address = form.address.data, city = form.city.data, dob=form.dob.data,gender=form.gender.data, mobile = form.mobile.data)
        db.session.add(new_user)
        db.session.commit()
        flash("You have successfully registered! Please login to continue.")
        return redirect(url_for('login'))
    
    return render_template("register.html", form=form)

class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)])
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)])
    submit = SubmitField("Login")

@app.route("/")
def index():
    appointments = Appointment.query.order_by(Appointment.date).all()
    return render_template("index.html", appointments=appointments)


# LOGIN
@app.route("/login", methods=['GET','POST'])
def login():
    form = LoginForm()    
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            return(redirect(url_for('home')))
        else:
            flash("Invalid username or password")
            return redirect(url_for('login'))



    return render_template("userlogin.html", form=form)


# DASHBOARD
@app.route("/home", methods=['GET','POST'])
@login_required
def home():
    appointments = Appointment.query.filter_by(user_id = current_user.id).all()
    return render_template("home.html", appointments=appointments)

# APPOINTMENT
@app.route("/appointment", methods=["GET", "POST"])
@login_required
def appointment():
    form = AppointmentForm()
    if form.validate_on_submit():
        slot = form.slot.data
        date = form.date.data
        appointment = Appointment(user_id = current_user.id, slot=slot, date=date)
        db.session.add(appointment)
        db.session.commit()
        return redirect(url_for("home"))
    return render_template("appointment.html", form=form)



# LOGOUT
@app.route("/logout", methods=['GET','POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.context_processor
def inject_datetime():
    return dict(datetime=datetime)

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)