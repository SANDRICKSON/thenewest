from flask import Flask, render_template, redirect, url_for, flash, request, session
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

limiter = Limiter(get_remote_address, app=app, default_limits=["5 per minute"])

# 📌 Email ვერიფიკაციის ტოკენის გენერაცია
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# Google OAuth კონფიგურაცია
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id='501759979349-up2l59bd01tg6qh38fctmdr27p8l3qse.apps.googleusercontent.com',  # ჩააგდე შენი Google Client ID
    client_secret='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',  # ჩააგდე შენი Google Client Secret
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    access_token_url='https://accounts.google.com/o/oauth2/token',
    client_kwargs={
        'scope': 'email',
    }
)

@app.route("/")
def index():
    return render_template("index.html", title="ვეფხისტყაოსანი")

# 📌 Google OAuth როუტი
@app.route('/login')
def login():
    redirect_uri = url_for('google_authorized', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/login/authorized')
def google_authorized():
    token = google.authorize_access_token()
    session['google_token'] = token
    return redirect(url_for('home'))

@google.tokengetter
def get_google_oauth_token():
    return session.get('google_token')

@app.route('/home')
@login_required
def home():
    if 'google_token' in session:
        user = google.get('plus/v1/people/me')
        return f'Hello, {user.data["displayName"]}!'
    return redirect(url_for('login'))

# 📌 Email ვერიფიკაციის ფუნქცია
def send_verification_email(user_email):
    token = generate_verification_token(user_email)
    confirm_url = url_for('confirm_email', token=token, _external=True)
    subject = "Email Verification"
    message_body = f"დააჭირეთ ამ ბმულს თქვენი ემაილის ვერიფიკაციისთვის: {confirm_url}"

    msg = Message(subject=subject, recipients=[user_email], body=message_body)
    mail.send(msg)

# 📌 პაროლის აღდგენის როუტი
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
    return render_template('forgot_password.html', form=form, title="პაროლის აღდგენა - ვეფხისტყაოსანი")

# 📌 პაროლის განახლების როუტი
@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = s.loads(token, salt='password-reset', max_age=3600)  # 1 საათი
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

@app.route('/confirm/<token>')
def confirm_email(token):
    email = confirm_verification_token(token)
    if not email:
        flash("ვერიფიკაციის ბმული არასწორია ან ვადა გაუვიდა!", "danger")
        return redirect(url_for('login'))

    user = User.query.filter_by(email=email).first()
    if user and not user.is_verified:
        user.is_verified = True
        user.save()
        flash("თქვენი ემაილი წარმატებით ვერიფიცირდა!", "success")
    elif user and user.is_verified:
        flash("თქვენი ემაილი უკვე ვერიფიცირებულია!", "info")

    return redirect(url_for('login'))

# 📌 რეგისტრაცია, პაროლის შეცვლა, მომხმარებლის პროფილი
@app.route("/profile")
@login_required
def profile():
    return render_template("profile.html", title="პროფილი - ვეფხისტყაოსანი")

@app.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    form = FormUpdateForm(obj=current_user)  # ფორმის შევსება მიმდინარე მომხმარებლის მონაცემებით
    changed_fields = []  # შევინახოთ რა შეიცვალა

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

    return render_template("settings.html", form=form, title="პარამეტრები - ვეფხისტყაოსანი")

def send_account_update_email(user, changed_fields):
    """აგზავნის ელფოსტას, როდესაც მომხმარებელი ცვლის მონაცემებს."""
    subject = "ანგარიშის მონაცემები შეიცვალა"
    changes = ", ".join(changed_fields)  # რა შეიცვალა კონკრეტულად
    message_body = f"""
    ძვირფასო {user.username}!

    თქვენს ანგარიშზე შეიცვალა შემდეგი მონაცემები: {changes}.
    თუ ეს თქვენ არ ყოფილხართ და გაქვთ ეჭვი, რომ თაღლითური შემოტევა იყო, გთხოვთ, მოგვწერეთ: vepkhistyaosaniproject@gmail.com

    მადლობა ყურადღებისთვის!
    """

    msg = Message(subject=subject, recipients=[user.email], body=message_body)
    mail.send(msg)

# 📌 რეგისტრაციის როუტი
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
        flash("თქვენს ელფოსტაზე გაგზავნილია ვერიფიკაციის ბმული!", "info")
        return redirect(url_for("login"))
    
    return render_template("register.html", form=form, title="რეგისტრაცია - ვეფხისტყაოსანი")

# 📌 ლოგინი, არგუმენტების გადაცემით
@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for("index"))
    return render_template("login.html", form=form, title="ავტორიზაცია - ვეფხისტყაოსანი")

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route("/about")
def about():
    return render_template("about.html", title="პროექტის შესახებ - ვეფხისტყაოსანი")

@app.route("/contact", methods=["GET", "POST"])
def contact():
    form = MessageForm()
    if form.validate_on_submit():
        msg = Message('New Contact Form Submission',
                      recipients=['vepkhistyaosaniproject@gmail.com']) 
        msg.body = form.message.data  
        mail.send(msg)
        
        flash("Message sent!")
    return render_template("contact.html", form=form, title="კონტაქტი - ვეფხისტყაოსანი")

@app.route("/author")
def author():
    return render_template("author.html", title="ავტორის შესახებ - ვეფხისტყაოსანი")

if __name__ == "__main__":  
    app.run(debug=True)
