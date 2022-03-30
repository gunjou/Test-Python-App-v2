import random, string
from flask import Blueprint, render_template, request, flash, redirect, session, url_for
from flask_login import login_user, login_required, logout_user, current_user

from api import views
from .models import *
from . import db
from werkzeug.security import generate_password_hash, check_password_hash


auth = Blueprint('auth', __name__)

@auth.route('/init-data', methods=['GET', 'POST'])
def init_data():
    if request.method == 'POST':
        namaAdmin = request.form.get('namaAdmin')
        perusahaan = request.form.get('perusahaan')
        email=namaAdmin+'@'+perusahaan+'.com'

        user = Profile.query.filter_by(email=email).first()
        if user:
            flash('Email already exists.', category='error')
        if len(namaAdmin) < 1:
            flash('Nama tidak boleh kosong', category='error')
        elif len(perusahaan) < 1:
            flash('Perusahaan tidak boleh kosong', category='error')
        else:
            char = random.sample(string.ascii_lowercase+string.digits, 6)
            char = "".join(char)
            new_profile = Profile(email=namaAdmin+'@'+perusahaan+'.com', password=generate_password_hash(char, method='sha256'), profile='Admin')
            db.session.add(new_profile)
            db.session.commit()
            # login_user(user, remember=True)
            flash('Akun berhasil dibuat', category='success')
            # print(new_profile)
            return render_template('create_user_success.html', 
            email=namaAdmin+'@'+perusahaan+'.com',
            password=char,
            profile='Admin'
            )

    return render_template('init_data.html')

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        profile = request.form.get('profile')

        user = Profile.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                flash('Login berhasil', category='success')
                login_user(user, remember=True) 
                return redirect(url_for('views.home'))
            else:
                flash('Password salah, coba lagi', category='error')
        else:
            flash('Email yang anda masukkan salah!', category='error')

        if len(email) < 1:
            flash('Email tidak boleh kosong', category='error')
        elif len(password) < 1:
            flash('Password tidak boleh kosong', category='error')
        elif len(profile) < 1:
            flash('Profile tidak boleh kosong', category='error')
        else:
            pass
            # flash('Login Success', category='success')

    return render_template('login.html')

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))

@auth.route('/ubah-password', methods=['GET', 'POST'])
@login_required
def ubah_password():
    if request.method == 'POST':
        passwordAsli = request.form.get('passwordAsli')
        passwordBaru1 = request.form.get('passwordBaru1')
        passwordBaru2 = request.form.get('passwordBaru2')

        user = Profile.query.filter_by(email=current_user.email).first()
        if check_password_hash(user.password, passwordAsli):
            if passwordBaru1 == passwordBaru2:
                user.password = generate_password_hash(passwordBaru1, method='sha256')
                db.session.commit()
                flash('Password berhasil dirubah', category='success')
            else:
                flash('Password konfirmasi salah', category='error')
        else:
            flash('Password lama salah', category='error')

    return render_template('ubah_password.html')