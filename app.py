from flask import render_template, redirect, url_for, flash, request, session
from flask_login import login_user, logout_user, current_user, login_required
from werkzeug.security import check_password_hash, generate_password_hash
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadTimeSignature
from flask_mail import Message
from extensions import app, mail, db
from models import User
from authlib.integrations.flask_client import OAuth
from forms import RegisterForm, MessageForm, LoginForm, UpdateForm, ForgotPasswordForm, ResetPasswordForm, FormUpdateForm
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# OAuth setup
oauth = OAuth(app)

google = oauth.register(
    'google',
    client_id='YOUR_GOOGLE_CLIENT_ID',
    client_secret='YOUR_GOOGLE_CLIENT_SECRET',
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    access_token_url='https://accounts.google.com/o/oauth2/token',
    refresh_token_url=None,
    redirect_uri='YOUR_REDIRECT_URI',
    client_kwargs={'scope': 'openid profile email'},
)

# Flask-Limiter setup
limiter = Limiter(get_remote_address, app=app, default_limits=["5 per minute"])

# Serializer for email verification token
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])


# Google login route
@app.route('/google_login')
def google_login():
    return google.authorize(callback=url_for('google_callback', _external=True))


# Google callback route
@app.route('/login/callback')
def google_callback():
    response = google.authorized_response()
    if response is None or response.get('access_token') is None:
        return "Access denied: reason={} error={}".format(
            request.args['error_reason'],
            request.args['error_description']
        )

    session['google_token'] = (response['access_token'], '')
    user_info = google.get('userinfo')

    email = user_info.data['email']
    user = User.query.filter_by(email=email).first()

    if not user:
        user = User(username=user_info.data['name'], email=email, is_verified=True)
        db.session.add(user)
        db.session.commit()

    login_user(user)
    return redirect(url_for('profile'))


# Token getter for Google OAuth
@google.tokengetter
def get_google_oauth_token():
    return session.get('google_token')


# Email sending helper function for account updates
def send_account_update_email(user, changed_fields):
    subject = "ანგარიშის მონაცემები შეიცვალა"
    changes = ", ".join(changed_fields)
    message_body = f"""
    ძვირფასო {user.username}!
    თქვენს ანგარიშზე შეიცვალა შემდეგი მონაცემები: {changes}.
    თუ ეს თქვენ არ ყოფილხართ და გაქვთ ეჭვი, რომ თაღლითური შემოტევა იყო, გთხოვთ, მოგვწერეთ: vepkhistyaosaniproject@gmail.com
    მადლობა ყურადღებისთვის!
    """
    msg = Message(subject=subject, recipients=[user.email], body=message_body)
    mail.send(msg)


# Password recovery route
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    form = ForgotPasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            token = s.dumps(user.email, salt='password-reset')
            reset_url = url_for('reset_password', token=token, _external=True)
            msg = Message('პაროლის აღდგენა', recipients=[user.email])
            msg.body = f"პაროლის აღსადგენად დააჭირეთ ამ ბმულს: {reset_url}"
            mail.send(msg)
            flash('ელ.ფოსტა გაგზავნილია!', 'success')
            return redirect(url_for('login'))
        else:
            flash('ამ ელ.ფოსტით მომხმარებელი არ მოიძებნა.', 'danger')
    return render_template('forgot_password.html', form=form, title="პაროლის აღდგენა")


# Route to reset the password
@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = s.loads(token, salt='password-reset', max_age=3600)
    except (SignatureExpired, BadTimeSignature):
        flash('ბმული არასწორია ან ვადა გაუვიდა!', 'danger')
        return redirect(url_for('forgot_password'))

    user = User.query.filter_by(email=email).first()
    if not user:
        flash('მომხმარებელი ვერ მოიძებნა!', 'danger')
        return redirect(url_for('forgot_password'))

    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.password = generate_password_hash(form.password.data)
        db.session.commit()
        flash('პაროლი წარმატებით განახლდა!', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html', form=form)


# Route for user settings
@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    form = FormUpdateForm(obj=current_user)
    changed_fields = []

    if form.validate_on_submit():
        if current_user.username != form.username.data:
            changed_fields.append("მომხმარებლის სახელი")
            current_user.username = form.username.data

        if current_user.email != form.email.data:
            changed_fields.append("ელ.ფოსტა")
            current_user.email = form.email.data

        if current_user.birthday != form.birthday.data:
            changed_fields.append("დაბადების თარიღი")
            current_user.birthday = form.birthday.data

        if current_user.country != form.country.data:
            changed_fields.append("ქვეყანა")
            current_user.country = form.country.data

        if current_user.gender != form.gender.data:
            changed_fields.append("სქესი")
            current_user.gender = form.gender.data

        if form.password.data:
            changed_fields.append("პაროლი")
            current_user.password = generate_password_hash(form.password.data)

        db.session.commit()

        if changed_fields:
            send_account_update_email(current_user, changed_fields)

        flash("მონაცემები წარმატებით განახლდა!", "success")
        return redirect(url_for("profile"))

    return render_template("settings.html", form=form, title="პარამეტრები")


# Email verification token generation and verification functions
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


def send_verification_email(user_email):
    token = generate_verification_token(user_email)
    confirm_url = url_for('confirm_email', token=token, _external=True)
    subject = "Email Verification"
    message_body = f"დააჭირეთ ამ ბმულს თქვენი ემაილის ვერიფიკაციისთვის: {confirm_url}"

    msg = Message(subject=subject, recipients=[user_email], body=message_body)
    mail.send(msg)


# Email confirmation route
@app.route('/confirm/<token>')
def confirm_email(token):
    email = confirm_verification_token(token)
    if not email:
        flash("ვერიფიკაციის ბმული არასწორია ან ვადა გაუვიდა!", "danger")
        return redirect(url_for('login'))

    user = User.query.filter_by(email=email).first()
    if user and not user.is_verified:
        user.is_verified = True
        db.session.commit()
        flash("თქვენი ემაილი წარმატებით ვერიფიკირდა!", "success")
    elif user and user.is_verified:
        flash("თქვენი ემაილი უკვე ვერიფიცირებულია!", "info")

    return redirect(url_for('login'))


# Login route
@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for("index"))
    return render_template("login.html", form=form, title="ავტორიზაცია")


# Logout route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


# Profile route
@app.route("/profile")
@login_required
def profile():
    return render_template("profile.html", title="პროფილი")


# Register route
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
        db.session.add(user)
        db.session.commit()
        send_verification_email(user.email)
        flash("თქვენს ელფოსტაზე გაგზავნილია ვერიფიკაციის ბმული!", "info")
        return redirect(url_for("login"))
    return render_template("register.html", form=form, title="რეგისტრაცია")


# Main route
@app.route("/")
def index():
    return render_template("index.html", title="ვეფხისტყაოსანი")


if __name__ == "__main__":
    app.run(debug=True)
