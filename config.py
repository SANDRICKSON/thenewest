from flask_mail import Mail

mail = Mail()

def init_app(app):
    app.config['MAIL_SERVER'] = 'smtp.gmail.com'
    app.config['MAIL_PORT'] = 587
    app.config['MAIL_USE_TLS'] = True
    app.config['MAIL_USERNAME'] = 'vepkhistyaosaniproject@gmail.com'
    app.config['MAIL_PASSWORD'] = 'vymi jkng kwze aphz'
    app.config['MAIL_DEFAULT_SENDER'] = 'vepkhistyaosaniproject@gmail.com'

    mail.init_app(app)


GOOGLE_CLIENT_ID = "501759979349-up2l59bd01tg6qh38fctmdr27p8l3qse.apps.googleusercontent.com"
GOOGLE_CLIENT_SECRET = "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"
