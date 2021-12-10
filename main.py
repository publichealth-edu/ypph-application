
from flask import Flask, render_template, send_file, redirect, url_for, flash, abort
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField, FileField
from wtforms.validators import DataRequired, Length, Email
from flask_bootstrap import Bootstrap
from flask_uploads import UploadSet, configure_uploads, DOCUMENTS, UploadSet
import smtplib
from werkzeug.security import generate_password_hash, check_password_hash
import os
import re
from io import BytesIO
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
import sys
import logging


FROM_EMAIL = os.environ.get("FROM_EMAIL")
PASSWORD = os.environ.get("PASSWORD")
TO_EMAIL = os.environ.get("TO_EMAIL")

app = Flask(__name__)
app.logger.addHandler(logging.StreamHandler(sys.stdout))
app.logger.setLevel(logging.ERROR)
Bootstrap(app)
app.secret_key = os.environ.get("SECRET_KEY")
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
if app.config['SQLALCHEMY_DATABASE_URI'].startswith("postgres://"):
    app.config['SQLALCHEMY_DATABASE_URI'] = app.config['SQLALCHEMY_DATABASE_URI'].replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(250), nullable=False)
    password = db.Column(db.String(250), nullable=False)
    

class Uploads(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    applicant_name = db.Column(db.String(300), unique=False, nullable=False)
    applicant_email = db.Column(db.String(300), unique=False, nullable=False)
    applicant_phone = db.Column(db.String(300), unique=False, nullable=False)
    applicant_citizen = db.Column(db.String(300), unique=False, nullable=False)
    applicant_residency = db.Column(db.String(300), unique=False, nullable=False)
    applicant_category = db.Column(db.String(300), unique=False, nullable=False)
    statement_name = db.Column(db.String(300), unique=False, nullable=False)
    statement_data = db.Column(db.LargeBinary)
    resume_name = db.Column(db.String(300), unique=False, nullable=False)
    resume_data = db.Column(db.LargeBinary)
    certificate_name = db.Column(db.String(300), unique=False, nullable=False)
    certificate_data = db.Column(db.LargeBinary)
    reference_name = db.Column(db.String(300), unique=False, nullable=False)
    reference_data = db.Column(db.LargeBinary)
    
    

    def __repr__(self):
        return f"<Uploads {self.title}>"

db.create_all()

class MyForm(FlaskForm):
    fname = StringField(label='What is your first name?', validators=[DataRequired()])
    mname = StringField(label='What is your middle name? (Skip if not applicable)')
    lname = StringField(label='What is your last name?', validators=[DataRequired()])
    email = StringField(label='What is your email address?', validators=[Email(), DataRequired(), Length(min=6)])
    phone = StringField(label="What is your phone number (Please add your country\n's dialing code)", validators=[DataRequired()])
    citizen = StringField(label='What is your country of birth?', validators=[DataRequired()])
    residence = StringField(label='What is your country of residence?', validators=[DataRequired()])
    category = SelectField('What membership category are you applying for?', choices=["", "Graduate Member", "Associate Member", "Member", "Fellow", "Institution Member"], validators=[DataRequired()])
    support = FileField(label='Please upload supporting statement here', validators=[DataRequired()])
    resume = FileField(label='Please upload your resume here', validators=[DataRequired()])
    cert = FileField(label='Please upload your certificate here', validators=[DataRequired()])
    reference = FileField(label='Please upload your reference here', validators=[DataRequired()])
    submit = SubmitField(label='Submit')

class RegisterForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Sign me up!")

class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Let me in!")

login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.id != 2:
            return abort(403)
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/download/<id>', methods=["GET"])
@login_required
def downloads(id):
    item = Uploads.query.get(id)
    return send_file(BytesIO(item.statement_data), mimetype='application/pdf', as_attachment=True, attachment_filename=item.statement_name)

@app.route('/downloadr/<id>', methods=["GET"])
@login_required
def downloadr(id):
    item = Uploads.query.get(id)
    return send_file(BytesIO(item.resume_data), mimetype='application/pdf', as_attachment=True, attachment_filename=item.resume_name)

@app.route('/downloadc/<id>', methods=["GET"])
@login_required
def downloadc(id):
    item = Uploads.query.get(id)
    return send_file(BytesIO(item.certificate_data), mimetype='application/pdf', as_attachment=True, attachment_filename=item.certificate_name)

@app.route('/downloadrr/<id>', methods=["GET"])
@login_required
def downloadrr(id):
    item = Uploads.query.get(id)
    return send_file(BytesIO(item.reference_data), mimetype='application/pdf', as_attachment=True, attachment_filename=item.reference_name)

@app.route('/files', methods=["GET"])
@login_required
def files():
    items = Uploads().query.all()
    return render_template('files.html', items=items, logged_in=current_user.is_authenticated)

@app.route("/delete/<int:id>")
@login_required
def delete(id):
    item = Uploads.query.get(id)
    db.session.delete(item)
    db.session.commit()
    return render_template (url_for('files'))

@app.route('/success')
def success():
    return render_template('success.html')

@app.route('/apply', methods=['GET', 'POST'])
def login():
    form = MyForm()
    if form.validate_on_submit():
        fname = form.fname.data
        mname = form.mname.data
        lname = form.lname.data
        email = form.email.data
        phone = form.phone.data
        citizen = form.citizen.data
        residence = form.residence.data
        category = form.category.data
        support = form.support.data
        resume = form.resume.data
        cert = form.cert.data
        reference = form.reference.data

        newfile = Uploads(applicant_name=f"{fname} {mname} {lname}", applicant_email=email, applicant_phone=phone, applicant_citizen=citizen, applicant_residency=residence, applicant_category=category, statement_name=support.filename, statement_data=support.read(), resume_name=resume.filename, resume_data=resume.read(), certificate_name=cert.filename, certificate_data=cert.read(), reference_name=reference.filename, reference_data=reference.read())
        db.session.add(newfile)
        db.session.commit()
        
        
        with smtplib.SMTP("smtp.mail.yahoo.com") as connection:
            connection.starttls()
            connection.login(user=FROM_EMAIL, password=PASSWORD)
            connection.sendmail(
                from_addr=FROM_EMAIL,
                to_addrs=TO_EMAIL,
                msg=f"Subject: New APH Membership Application\n\nFirst name: {fname}\n\nMiddle name: {mname}\n\nLast name: {lname}\n\nEmail: {email}\n\nPhone: {phone}\n\nCountry of Citizenship: {citizen}\n\nCountry of Residence: {residence}\n\nCategory being applied for: {category}"
                    )
        
        
        return render_template('success.html')
    return render_template('login.html', form=form)

# @app.route('/register', methods=["GET", "POST"])
# def register():
#     form = RegisterForm()
#     if form.validate_on_submit():
    
#         hash_and_salted_password = generate_password_hash(
#             form.password.data,
#             method='pbkdf2:sha256',
#             salt_length=8
#         )
#         new_user = User(
#             username=form.username.data,
#             password=hash_and_salted_password,
#         )
#         db.session.add(new_user)
#         db.session.commit()
        
#         #Log in and authenticate user after adding details to database.
#         login_user(new_user)
        
#         return redirect(url_for("files"))

#     return render_template("register.html", form=form)


@app.route('/signin', methods=["GET", "POST"])
def signin():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        
        #Find user by email entered.
        user = User.query.filter_by(username=username).first()
        
        if user == None:
            flash("This email does not exist in our database.")
            return redirect(url_for("signin"))
        elif check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('files'))
        else:
            flash('Incorrect password')
            return redirect (url_for('signin'))

    return render_template("signin.html", form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('signin'))

if __name__ == "__main__":
    app.run(debug=True)

