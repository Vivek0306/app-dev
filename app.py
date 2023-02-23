from flask import Flask, render_template, request, url_for, session, redirect, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from flask_migrate import Migrate
from wtforms import *#form creation
from wtforms.validators import *
from flask_bcrypt import Bcrypt
from datetime import datetime, date
import datetime


# ******CONFIG******

app = Flask(__name__)
app.debug = True
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.sqlite'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
app.config['SECRET_KEY'] ='secretkey'


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "userlogin"


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# CUSTOM FUNCTIONS
today = date.today()

def calculate_age(born):
    age = today.year - born.year - ((today.month, today.day) < (born.month, born.day))
    if age <= 0:
        return 1
    else:
        return age
app.jinja_env.filters['calculate_age'] = calculate_age

def order_by_slot(appointment):
    return {'morning': 1, 'afternoon': 2, 'evening': 3}[appointment.slot]

# PORGRAM MODELS

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False, unique=True)
    password = db.Column(db.String(50), nullable=False)
    name = db.Column(db.String(50), nullable=False)
    address = db.Column(db.String(80))
    city = db.Column(db.String(30))
    dob = db.Column(db.Date, nullable=False)
    gender = db.Column(db.String(10), nullable=False)
    is_doctor = db.Column(db.Boolean, default=False, nullable=False)
    mobile = db.Column(db.Integer)
        
class Doctor(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    username = db.Column(db.String(50), nullable=False, unique=True)
    password = db.Column(db.String(50), nullable=False)

class Appointment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    slot = db.Column(db.String(50), nullable=False)
    date = db.Column(db.Date, nullable=False)
    status = db.Column(db.Boolean, default=False, nullable=False)


# ****** FORMS *******

class Doc_RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "User Name"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})
    fullname = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Full Name"})
    gender = RadioField('Gender', choices=[('Male'),('Female'),('Other')])
    dob = DateField(validators=[InputRequired()],render_kw={"placeholder": "Date of Birth"})
    submit = SubmitField("Register")

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(username=username.data).first()
        if existing_user_username:
            raise ValidationError("Username already exists.")

class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "User Name"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})
    name = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Full Name"})
    gender = RadioField('Gender', choices=[('Male'),('Female'),('Other')])
    address = StringField(validators=[InputRequired(), Length(min=4, max=100)], render_kw={"placeholder": "Address"})
    mobile = StringField(validators=[InputRequired(), Length(min=10, max=12)], render_kw={"placeholder": "Mobile No."})
    city = StringField(validators=[InputRequired(), Length(min=4, max=30)], render_kw={"placeholder": "City"})
    dob = DateField(validators=[InputRequired()],render_kw={"placeholder": "Date of Birth"})
    submit = SubmitField("Register")

    # confirm = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Confirm Password"})
    def validate_username(self, username):
        existing_user_username = User.query.filter_by(username=username.data).first()
        if existing_user_username:
            raise ValidationError("Username already exists.")
    
class EditForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "User Name"}, name='username')
    name = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Full Name"}, name='name')
    gender = RadioField('Gender', choices=[('Male'),('Female'),('Other')], name='gender')
    address = StringField(validators=[InputRequired(), Length(min=4, max=100)], render_kw={"placeholder": "Address"}, name='address')
    mobile = StringField(validators=[InputRequired(), Length(min=10, max=12)], render_kw={"placeholder": "Mobile No."}, name='mobile')
    city = StringField(validators=[InputRequired(), Length(min=4, max=30)], render_kw={"placeholder": "City"}, name='city')
    dob = DateField(validators=[InputRequired()],render_kw={"placeholder": "Date of Birth"}, name='dob')
    submit = SubmitField("Save Changes")

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(username=username.data).first()
        if existing_user_username:
            raise ValidationError("Username already exists.")


class AppointmentForm(FlaskForm):
    slot = SelectField("Appointment Slot", choices=[("morning", "Morning (9am-12pm)"), ("afternoon", "Afternoon (1pm-4pm)"), ("evening", "Evening (5pm-8pm)")], validators=[InputRequired()])
    date = DateField("Appointment Date",validators=[InputRequired()])
    submit = SubmitField("Book Appointment",validators=[InputRequired()])

class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)])
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)])
    submit = SubmitField("Login")

# ******** ROUTES ********
# REGISTRATION
@app.route("/register", methods=['GET','POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password, name=form.name.data, address = form.address.data, city = form.city.data, dob=form.dob.data,gender=form.gender.data, is_doctor = False, mobile = form.mobile.data)
        db.session.add(new_user)
        db.session.commit()
        flash("You have successfully registered! Please login to continue.")
        return redirect(url_for('userlogin'))
    
    return render_template("register.html", form=form)

@app.route("/doctorRegister", methods=['GET','POST'])
def doctorRegister():
    form = Doc_RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password, name=form.name.data, dob=form.dob.data, gender=form.gender.data, is_doctor = True)

        db.session.add(new_user)
        db.session.commit()
        flash("You have successfully registered! Please login to continue.")
        return redirect(url_for('doctorlogin'))
    
    return render_template("doctorRegister.html", form=form)

@app.route("/")
def index():
    appointments = Appointment.query.order_by(Appointment.date).all()
    return render_template("index.html", appointments=appointments)


# LOGIN
@app.route("/userlogin", methods=['GET','POST'])
def userlogin():
    form = LoginForm()    
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            return(redirect(url_for('home')))
        else:
            flash("Invalid username or password")
            return redirect(url_for('userlogin'))
    return render_template("userlogin.html", form=form)
    

@app.route("/doctorlogin", methods=['GET','POST'])
def doctorlogin():
    form = LoginForm()    
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            return(redirect(url_for('home')))
        else:
            flash("Invalid username or password")
            return redirect(url_for('doctorlogin'))
    return render_template("doctorlogin.html", form=form)


# DASHBOARD
@app.route("/home", methods = ['GET', 'POST'])
@login_required
def home():
    check_user = User.query.filter_by(id = current_user.id).first()
    if check_user.is_doctor:
        past_appointments = Appointment.query.filter(Appointment.date < today).all()
        for appointment in past_appointments:
            db.session.delete(appointment)
        db.session.commit()

        appointments = db.session.query(Appointment, User).join(User).filter(Appointment.date == date.today()).order_by(db.case({
            'morning': 1,
            'afternoon': 2,
            'evening': 3
        }, value=Appointment.slot)).all()
        done_appointments = Appointment.query.filter_by(status=True).count()

    else:
        appointments = None
        done_appointments = None
    return render_template("home.html", appointments = appointments, done_appointments = done_appointments)



@app.route("/myappointments/<int:id>", methods=['GET','POST'])
@app.route("/myappointments/")
@login_required
def myappointments(id=None):
    check_user = User.query.filter_by(id = current_user.id).first()
    if check_user.is_doctor:
        appointments = db.session.query(Appointment, User).join(User).filter(Appointment.date == date.today()).filter(Appointment.status == False).order_by(db.case({
            'morning': 1,
            'afternoon': 2,
            'evening': 3
        }, value=Appointment.slot)).all()
    else:
        appointments = Appointment.query.filter_by(user_id = current_user.id).all()

    appointment = None
    if id is not None:
        appointment = db.session.query(Appointment, User).join(User).filter(Appointment.id == id).all()
    return render_template("myappointments.html", appointments=appointments, appointment=appointment, id=id)


@app.route("/profile", methods=['GET', 'POST'])
@login_required
def profile():
    return render_template("profile.html")

@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    form = EditForm(obj=current_user)
    if form.validate_on_submit():
        form.populate_obj(current_user)
        db.session.commit()
        return redirect(url_for('profile'))
    return render_template('edit_profile.html', form=form)

# APPOINTMENT
@app.route("/appointment", methods=["GET", "POST"])
@login_required
def appointment():
    form = AppointmentForm()
    if form.validate_on_submit():
        slot = form.slot.data
        date = form.date.data
        appointment = Appointment(user_id = current_user.id, slot=slot, date=date, status=False)
        db.session.add(appointment)
        db.session.commit()
        return redirect(url_for("myappointments"))
    return render_template("appointment.html", form=form)



@app.route('/delete_appointment/<int:id>', methods=['POST','GET'])
@login_required
def delete_appointment(id):
    appointment = Appointment.query.get(id)
    db.session.delete(appointment)
    db.session.commit()
    return redirect(url_for('myappointments'))

@app.route('/markDone/<int:id>', methods=['GET', 'POST'])
@login_required
def markDone(id):
    appointment = Appointment.query.get(id)
    appointment.status = True
    db.session.commit()
    return redirect(url_for('myappointments'))


# LOGOUT
@app.route("/logout", methods=['GET','POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('userlogin'))


@app.context_processor
def inject_datetime():
    return dict(datetime=datetime)

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)