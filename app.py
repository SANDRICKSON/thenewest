from flask import render_template, redirect, url_for, flash, request, session
from flask_login import login_user, logout_user, current_user, login_required
from werkzeug.security import check_password_hash, generate_password_hash
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadTimeSignature
from flask_mail import Message
from extensions import app, mail, db
from models import User
from forms import RegisterForm, MessageForm, LoginForm, UpdateForm, ForgotPasswordForm, ResetPasswordForm, FormUpdateForm
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from authlib.integrations.flask_client import OAuth

# Initialize OAuth for Google login
oauth = OAuth(app)
google = oauth.remote_app(
    'google',
    consumer_key=app.config['GOOGLE_CLIENT_ID'],
    consumer_secret=app.config['GOOGLE_CLIENT_SECRET'],
    request_token_params={'scope': 'email'},
    base_url='https://www.googleapis.com/oauth2/v1/',
    request_token_url=None,
    access_token_method='POST',
    access_token_url='https://accounts.google.com/o/oauth2/token',
    authorize_url='https://accounts.google.com/o/oauth2/auth',
)

# Initialize Flask-Limiter
limiter = Limiter(get_remote_address, app=app, default_limits=["5 per minute"])

# Initialize URLSafeTimedSerializer for email verification
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

app.config['GOOGLE_CLIENT_ID'] = '501759979349-up2l59bd01tg6qh38fctmdr27p8l3qse.apps.googleusercontent.com'  # ჩაანაცვლე ეს შენი რეალური კლიენტ აიდით
app.config['GOOGLE_CLIENT_SECRET'] = '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'  # ჩაანაცვლე ეს შენი რეალური სეკრეტ აიდით

# Google OAuth Routes
@app.route('/login/google')
def google_login():
    return google.authorize(callback=url_for('google_authorized', _external=True))

@app.route('/google_login/authorized')
def google_authorized():
    response = google.authorized_response()
    if response is None or response.get('access_token') is None:
        flash('Google authorization failed. Please try again.', 'danger')
        return redirect(url_for('index'))

    session['google_token'] = (response['access_token'], '')
    user_info = google.get('userinfo')
    user_data = user_info.data
    username = user_data['name']
    email = user_data['email']
    
    # Check or create user
    user = User.query.filter_by(email=email).first()
    if not user:
        user = User(username=username, email=email)
        db.session.add(user)
        db.session.commit()

    login_user(user)
    flash(f'Hello, {username}!', 'success')
    return redirect(url_for('profile'))

@google.tokengetter
def get_google_oauth_token():
    return session.get('google_token')


# Error Handlers
@app.errorhandler(429)
def too_many_requests(error):
    return render_template('429.html', title="Too Many Requests"), 429

@app.errorhandler(401)
def unauthorized(error):
    return render_template('401.html', title="Unauthorized"), 401

@app.errorhandler(500)
def internal_server_error(error):
    return render_template('500.html', title="Internal Server Error"), 500

@app.errorhandler(502)
def bad_gateway(error):
    return render_template('502.html', title="Bad Gateway"), 502

@app.errorhandler(503)
def service_unavailable(error):
    return render_template('503.html', title="Service Unavailable"), 503

@app.errorhandler(504)
def gateway_timeout(error):
    return render_template('504.html', title="Gateway Timeout"), 504

@app.errorhandler(404)
def page_not_found(error):
    return render_template('404.html', title="Page Not Found"), 404


# Security Headers
@app.after_request
def add_security_headers(response):
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


# Route to display settings page
@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    form = FormUpdateForm(obj=current_user)
    changed_fields = []

    if form.validate_on_submit():
        if current_user.username != form.username.data:
            changed_fields.append("Username")
            current_user.username = form.username.data

        if current_user.email != form.email.data:
            changed_fields.append("Email")
            current_user.email = form.email.data

        if current_user.birthday != form.birthday.data:
            changed_fields.append("Birthday")
            current_user.birthday = form.birthday.data

        if current_user.country != form.country.data:
            changed_fields.append("Country")
            current_user.country = form.country.data

        if current_user.gender != form.gender.data:
            changed_fields.append("Gender")
            current_user.gender = form.gender.data

        if form.password.data:
            changed_fields.append("Password")
            current_user.password = generate_password_hash(form.password.data)

        db.session.commit()

        if changed_fields:
            send_account_update_email(current_user, changed_fields)

        flash("Account updated successfully!", "success")
        return redirect(url_for("profile"))

    return render_template("settings.html", form=form, title="Settings")


# Send account update email
def send_account_update_email(user, changed_fields):
    subject = "Account Data Updated"
    changes = ", ".join(changed_fields)
    message_body = f"Dear {user.username},\n\nThe following information has been updated: {changes}. If this was not you, please contact us immediately.\n\nThank you!"
    msg = Message(subject=subject, recipients=[user.email], body=message_body)
    mail.send(msg)


# Forgot Password Flow
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    form = ForgotPasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            token = s.dumps(user.email, salt='password-reset')
            reset_url = url_for('reset_password', token=token, _external=True)
            msg = Message('Password Reset', recipients=[user.email])
            msg.body = f"Click here to reset your password: {reset_url}"
            mail.send(msg)
            flash('Password reset email sent!', 'success')
            return redirect(url_for('login'))
        else:
            flash('No account found with that email address.', 'danger')
    return render_template('forgot_password.html', form=form, title="Forgot Password")


# Reset Password Flow
@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = s.loads(token, salt='password-reset', max_age=3600)
    except (SignatureExpired, BadTimeSignature):
        flash('The link is invalid or has expired!', 'danger')
        return redirect(url_for('forgot_password'))

    user = User.query.filter_by(email=email).first()
    if not user:
        flash('User not found!', 'danger')
        return redirect(url_for('forgot_password'))

    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.password = generate_password_hash(form.password.data)
        db.session.commit()
        flash('Password updated successfully!', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html', form=form)


# Email Verification Functions
def send_verification_email(user_email):
    token = generate_verification_token(user_email)
    confirm_url = url_for('confirm_email', token=token, _external=True)
    subject = "Email Verification"
    message_body = f"Please click the link to verify your email: {confirm_url}"

    msg = Message(subject=subject, recipients=[user_email], body=message_body)
    mail.send(msg)

def generate_verification_token(email):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    return serializer.dumps(email, salt='email-confirm')

def confirm_verification_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        email = serializer.loads(token, salt='email-confirm', max_age=expiration)
    except:
        return False
    return email

@app.route('/confirm/<token>')
def confirm_email(token):
    email = confirm_verification_token(token)
    if not email:
        flash("The verification link is invalid or expired.", "danger")
        return redirect(url_for('login'))

    user = User.query.filter_by(email=email).first()
    if user and not user.is_verified:
        user.is_verified = True
        user.save()
        flash("Your email has been successfully verified!", "success")
    elif user and user.is_verified:
        flash("Your email is already verified.", "info")

    return redirect(url_for('login'))


# Routes for Admin and User Management
@app.route("/admin/users")
@login_required
def view_users():
    if current_user.username == "admin":
        users = User.query.all()
        return render_template("admin_users.html", users=users, title="Users")
    else:
        flash("Unauthorized access", "danger")
        return redirect(url_for('noadmin'))

@app.route("/admin")
@login_required
def admin():
    if current_user.username == "admin":
        return render_template("admin.html", title="Admin Dashboard")
    else:
        flash("Unauthorized access", "danger")
        return redirect(url_for('noadmin'))


# User Profile and Registration
@app.route("/profile")
@login_required
def profile():
    return render_template("profile.html", title="Profile")

@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        user = User(
            username=form.username.data,
            email=form.email.data,
            password=form.password.data,
            birthday=form.birthday.data,
            country=form.country.data,
            gender=form.gender.data,
            is_verified=False
        )
        user.create()
        send_verification_email(user.email)
        flash("Verification email sent!", "info")
        return redirect(url_for("login"))
    return render_template("register.html", form=form, title="Register")


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login():
    form = LoginForm()
    if form.validate_on_submit():
        identifier = form.identifier.data
        password = form.password.data
        user = User.query.filter((User.username == identifier) | (User.email == identifier)).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash("Login successful!", "success")
            return redirect(url_for("index"))
        else:
            flash("Invalid credentials.", "danger")
    return render_template("login.html", form=form, title="Login")


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


# Static Pages
@app.route("/about")
def about():
    return render_template("about.html", title="About")

@app.route("/contact", methods=["GET", "POST"])
def contact():
    form = MessageForm()
    if form.validate_on_submit():
        try:
            msg = Message('New Message', recipients=['contact@website.com'])
            msg.sender = current_user.email
            msg.body = form.message.data
            mail.send(msg)
            flash("Message sent!", "success")
            return render_template("success.html", title="Message Sent")
        except Exception as e:
            flash("Message failed to send. Please try again.", "danger")
    return render_template("contact.html", form=form, title="Contact")


@app.route("/privacy")
def privacy():
    return render_template("privacy.html", title="Privacy Policy")


if __name__ == "__main__":
    app.run(debug=True)
