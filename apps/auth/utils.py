from flask import  make_response, render_template, current_app, url_for
from io import BytesIO
import qrcode
from datetime import datetime
from flask_babel import gettext as _
from weasyprint import HTML
from ..models.general.company import Company
import base64
from itsdangerous import URLSafeTimedSerializer
from werkzeug.utils import secure_filename
import os
import requests
from sqlalchemy.orm import joinedload
import sys
from pathlib import Path

def get_app_data_path():
    """Get cross-platform persistent user data directory"""
    if getattr(sys, 'frozen', False):  # Running from PyInstaller
        base = os.path.join(os.path.expanduser('~'), 'RessyncData')
    else:
        base = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'instance')

    os.makedirs(base, exist_ok=True)
    return base

def create_qr_code(data):
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(data)
    qr.make(fit=True)
    qr_img = qr.make_image(fill='black', back_color='white')

    qr_code_io = BytesIO()
    qr_img.save(qr_code_io, format='PNG')
    qr_code_io.seek(0)

    return qr_code_io

def generate_invoice_id():
    import random
    import datetime

    date_str = datetime.datetime.now().strftime("%Y%m%d")
    random_number = random.randint(1000, 9999)
    invoice_id = f"{date_str}-{random_number}"

    return invoice_id


def generate_reset_token(user, expiration=3600):
    s = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    return s.dumps({'reset': user.id}, salt=current_app.config['SECURITY_PASSWORD_SALT'])

def confirm_reset_token(token, expiration=3600):
    s = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    try:
        data = s.loads(token, salt=current_app.config['SECURITY_PASSWORD_SALT'], max_age=expiration)
    except:
        return False
    return data['reset']

def save_file_locally(file, folder_name):
    base_path = os.path.join(get_app_data_path(), folder_name)
    os.makedirs(base_path, exist_ok=True)

    filename = secure_filename(file.filename)
    full_path = os.path.join(base_path, filename)
    file.save(full_path)

    return {
        "absolute_path": full_path,
        "relative_url": url_for('auth.local_files', folder=folder_name, filename=filename, _external=True)
    }


def get_resource_path(folder):
    return os.path.join(get_app_data_path(), folder)



def check_internet_connection():
    url = "https://www.google.com"
    timeout = 8
    try:
        response = requests.get(url, timeout=timeout)
        return True if response.status_code == 200 else False
    except requests.ConnectionError:
        return False
    