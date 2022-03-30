from cgitb import text
from flask import Blueprint, render_template
from flask_login import login_required, current_user


views = Blueprint('views', __name__)

@views.route('/')
@views.route('/index')
@login_required
def home():
    return render_template('home.html')

@views.route('/create-user-success')
def create_user_success():
    return render_template('create_user_success.html')