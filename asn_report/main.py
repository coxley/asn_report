from flask import (Flask, Blueprint)
from flask.ext.sqlalchemy import SQLAlchemy
import chartkick

app = Flask(__name__)
db = SQLAlchemy(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///resources/asn_report.db'

# Set up chartkick
ck = Blueprint('ck_page',
               __name__,
               static_folder=chartkick.js(),
               static_url_path='/static')

app.register_blueprint(ck, url_prefix='/ck')
app.jinja_env.add_extension("chartkick.ext.charts")
# Finish chartkick

# Import at the end so Flask environment is setup
from asn_report import views

# Add URL rules to avoid circular imports
app.add_url_rule('/', view_func=views.asn)
