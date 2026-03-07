from flask import Flask, render_template, request, redirect, url_for, flash, send_file, send_from_directory, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from PIL import Image
from werkzeug.utils import secure_filename
from flask_mail import Mail, Message
from sqlalchemy.exc import IntegrityError
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from werkzeug.middleware.proxy_fix import ProxyFix
import cloudinary
import cloudinary.uploader
import base64
import os
import re
import datetime
from urllib.parse import urljoin

# ==============================
# APP CONFIGURATION
# ==============================

app = Flask(__name__)
app.secret_key = "SUPER_SECRET_CLASSIFIED_KEY"
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///stealthnet.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config["UPLOAD_FOLDER"] = os.path.join(app.root_path, "uploads")
app.config["ENCODED_FOLDER"] = os.path.join(app.config["UPLOAD_FOLDER"], "encoded")

os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
os.makedirs(app.config["ENCODED_FOLDER"], exist_ok=True)

ADMIN_BOOTSTRAP_USERNAME = os.environ.get("ADMIN_BOOTSTRAP_USERNAME", "ranjini")
ADMIN_BOOTSTRAP_PASSWORD = os.environ.get("ADMIN_BOOTSTRAP_PASSWORD", "ranjini!")
ADMIN_BOOTSTRAP_EMAIL = os.environ.get("ADMIN_BOOTSTRAP_EMAIL", "ranjini@stealthnet.local")

CLOUDINARY_CLOUD_NAME = os.environ.get("CLOUDINARY_CLOUD_NAME")
CLOUDINARY_API_KEY = os.environ.get("CLOUDINARY_API_KEY")
CLOUDINARY_API_SECRET = os.environ.get("CLOUDINARY_API_SECRET")
CLOUDINARY_FOLDER = os.environ.get("CLOUDINARY_FOLDER", "stealthnet")
BASE_URL = os.environ.get("BASE_URL", "https://stealthnet.onrender.com").rstrip("/")

CLOUDINARY_ENABLED = all([CLOUDINARY_CLOUD_NAME, CLOUDINARY_API_KEY, CLOUDINARY_API_SECRET])

if CLOUDINARY_ENABLED:
    cloudinary.config(
        cloud_name=CLOUDINARY_CLOUD_NAME,
        api_key=CLOUDINARY_API_KEY,
        api_secret=CLOUDINARY_API_SECRET,
        secure=True
    )

# -------- MAIL CONFIG --------
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'stealthnet01@gmail.com'
app.config['MAIL_PASSWORD'] = 'iaowqqpvwmbldkpb'
app.config['MAIL_DEFAULT_SENDER'] = 'stealthnet01@gmail.com'

mail = Mail(app)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# ==============================
# DATABASE MODELS
# ==============================

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

    role = db.Column(db.String(20), default="user")  # 👈 ADD THIS LINE

    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    login_attempts = db.Column(db.Integer, default=0)

class ActivityLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    action = db.Column(db.String(200))
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    user = db.relationship('User', backref='activities')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ==============================
# LOG FUNCTION
# ==============================

def log_activity(user_id, action):
    log = ActivityLog(user_id=user_id, action=action)
    db.session.add(log)
    db.session.commit()

def ensure_bootstrap_admin():
    user = User.query.filter_by(username=ADMIN_BOOTSTRAP_USERNAME).first()
    hashed_password = bcrypt.generate_password_hash(ADMIN_BOOTSTRAP_PASSWORD).decode("utf-8")

    if user:
        user.role = "admin"
        user.password = hashed_password
        if not user.email:
            user.email = ADMIN_BOOTSTRAP_EMAIL
    else:
        email_in_use = User.query.filter_by(email=ADMIN_BOOTSTRAP_EMAIL).first()
        email = ADMIN_BOOTSTRAP_EMAIL if not email_in_use else f"{ADMIN_BOOTSTRAP_USERNAME}@admin.local"
        user = User(
            username=ADMIN_BOOTSTRAP_USERNAME,
            email=email,
            password=hashed_password,
            role="admin"
        )
        db.session.add(user)

    db.session.commit()

def upload_encoded_image(file_path):
    result = cloudinary.uploader.upload(
        file_path,
        folder=CLOUDINARY_FOLDER,
        resource_type="image"
    )
    return result["secure_url"]

def build_public_url(path_or_url):
    if not path_or_url:
        return ""
    if path_or_url.startswith(("http://", "https://")):
        return path_or_url
    return urljoin(BASE_URL + "/", path_or_url.lstrip("/"))

# ==============================
# AES ENCRYPTION FUNCTIONS
# ==============================

def generate_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200000,
    )
    return kdf.derive(password.encode())

def encrypt_message(message, password):
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = generate_key(password, salt)
    cipher = AESGCM(key)
    ciphertext = cipher.encrypt(nonce, message.encode(), None)
    payload = salt + nonce + ciphertext
    return base64.urlsafe_b64encode(payload).decode()

def decrypt_message(encrypted_message, password):
    data = base64.urlsafe_b64decode(encrypted_message.encode())
    salt = data[:16]
    nonce = data[16:28]
    ciphertext = data[28:]
    key = generate_key(password, salt)
    cipher = AESGCM(key)
    return cipher.decrypt(nonce, ciphertext, None).decode()

# ==============================
# PASSWORD VALIDATION
# ==============================

def validate_password(password):
    if len(password) < 6:
        return "Password must be at least 6 characters long"

    if not re.search(r"[!@#$%^&*()_+=\-]", password):
        return "Password must contain at least one special character"

    return None

# ==============================
# STEGANOGRAPHY FUNCTIONS
# ==============================

from PIL import Image

def encode_image(image_path, secret_message, password, output_path):
    image = Image.open(image_path).convert("RGB")
    encoded = image.copy()

    secret_message = secret_message.strip()
    message = secret_message
    binary_msg = ''.join(format(ord(i), '08b') for i in message)

    # Store length in first 32 bits
    msg_length = format(len(binary_msg), '032b')
    binary_msg = msg_length + binary_msg

    pixels = encoded.load()
    width, height = encoded.size

    max_capacity = width * height * 3

    if len(binary_msg) > max_capacity:
        raise ValueError("Message too large for this image")

    data_index = 0

    for y in range(height):
        for x in range(width):
            pixel = list(pixels[x, y])

            for n in range(3):
                if data_index < len(binary_msg):
                    pixel[n] = pixel[n] & ~1 | int(binary_msg[data_index])
                    data_index += 1

            pixels[x, y] = tuple(pixel)

            if data_index >= len(binary_msg):
                break
        if data_index >= len(binary_msg):
            break

    encoded.save(output_path)

def decode_image(image_path, password):
    image = Image.open(image_path).convert("RGB")
    pixels = image.load()
    width, height = image.size

    binary_data = ""
    data_bits = []

    # Step 1: Read first 32 bits (message length)
    count = 0
    for y in range(height):
        for x in range(width):
            for n in range(3):
                binary_data += str(pixels[x, y][n] & 1)
                count += 1
                if count == 32:
                    break
            if count == 32:
                break
        if count == 32:
            break

    message_length = int(binary_data, 2)

    # Step 2: Read only required bits
    binary_data = ""
    count = 0
    total_bits_read = 0

    for y in range(height):
        for x in range(width):
            for n in range(3):

                if total_bits_read >= 32:
                    if count < message_length:
                        data_bits.append(str(pixels[x, y][n] & 1))
                        count += 1
                    else:
                        break

                total_bits_read += 1

            if count >= message_length:
                break
        if count >= message_length:
            break

    if count < message_length:
        return "INVALID_PASSWORD"

    binary_string = ''.join(data_bits)

    all_bytes = [binary_string[i:i+8] for i in range(0, len(binary_string), 8)]
    decoded = ''.join(chr(int(byte, 2)) for byte in all_bytes if len(byte) == 8)
    return decoded
# ==============================
# ROUTES
# ==============================

@app.route("/")
def welcome():
    return render_template("welcome.html")

# -------- SIGNUP --------
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":

        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")

        error = validate_password(password)
        if error:
            flash(error)
            return redirect(url_for("signup"))

        if User.query.filter_by(username=username).first():
            flash("Username already exists")
            return redirect(url_for("signup"))

        if User.query.filter_by(email=email).first():
            flash("Email already registered")
            return redirect(url_for("signup"))

        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")

        # ✅ If no users exist → first user becomes admin
        if User.query.count() == 0:
            role = "admin"
        else:
            role = "user"

        new_user = User(
            username=username,
            email=email,
            password=hashed_password,
            role=role
        )

        try:
            db.session.add(new_user)
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            flash("Email already exists")
            return redirect(url_for("signup"))

        flash("Account created successfully!")
        return redirect(url_for("login"))

    return render_template("signup.html")
# -------- LOGIN --------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        user = User.query.filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            user.login_attempts = 0
            db.session.commit()
            log_activity(user.id, "Login")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid Credentials")

    return render_template("login.html")

# -------- DASHBOARD --------
@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")

@app.route("/encoded/<path:filename>")
def serve_encoded(filename):
    return send_from_directory(app.config["ENCODED_FOLDER"], filename, as_attachment=False)

# -------- EMBED --------
@app.route("/embed", methods=["GET", "POST"])
@login_required
def embed():
    if request.method == "POST":
        image = request.files["image"]
        secret = request.form["secret"].strip()
        password = request.form["password"].strip()

        # Validate
        if not image or not secret or not password:
            flash("All fields are required.")
            return redirect(url_for("embed"))

        # Check allowed extensions
        if not image.filename.lower().endswith((".png", ".jpg", ".jpeg")):
            flash("Only PNG, JPG and JPEG formats are allowed.")
            return redirect(url_for("embed"))

        encrypted_secret = encrypt_message(secret, password)

        if image:
            # Save uploaded file
            filename = secure_filename(image.filename)

            os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

            temp_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            image.save(temp_path)

            # Convert ANY image to PNG (VERY IMPORTANT)
            img = Image.open(temp_path).convert("RGB")

            png_filename = os.path.splitext(filename)[0] + ".png"
            png_path = os.path.join(app.config["UPLOAD_FOLDER"], png_filename)

            img.save(png_path, "PNG")

            # Create output filename
            output_filename = "encoded_" + png_filename

            # Create output folder
            output_folder = app.config["ENCODED_FOLDER"]
            os.makedirs(output_folder, exist_ok=True)

            # Full output path
            output_path = os.path.join(output_folder, output_filename)

            # Encode image
            encode_image(png_path, encrypted_secret, password, output_path)

            image_url = url_for("serve_encoded", filename=output_filename)
            if CLOUDINARY_ENABLED:
                try:
                    image_url = upload_encoded_image(output_path)
                except Exception as e:
                    print("Cloudinary Error:", e)
                    flash("Cloud upload failed. Using local copy.")
            else:
                flash("Cloudinary not configured. Using temporary local storage.")

            # Log activity
            log_activity(current_user.id, "Embed Secret")

            return render_template(
                "generated.html",
                image_file=output_filename,
                image_url=image_url
            )

    return render_template("embed.html")
# -------- EXTRACT --------
@app.route('/extract', methods=['GET', 'POST'])
@login_required
def extract():
    if request.method == 'POST':
        image = request.files.get('image')
        password = request.form.get('password').strip()

        if not image or not password:
            flash("All fields required.")
            return redirect(url_for('extract'))

        filename = secure_filename(image.filename)
        upload_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        image.save(upload_path)

        result = decode_image(upload_path, password)

        if result == "INVALID_PASSWORD":
            flash("Authentication Failed — Incorrect Extraction Key")
            return redirect(url_for('extract'))

        try:
            decrypted_message = decrypt_message(result, password)
        except:
            flash("Invalid password or corrupted data")
            return redirect(url_for('extract'))

        log_activity(current_user.id, "Extract Secret")

        return render_template("result.html", decrypted_message=decrypted_message)

    return render_template("extract.html")

# -------- LOGOUT --------
@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("welcome"))

# -------- SHARE EMAIL --------

@app.route("/share-email", methods=["POST"])
@login_required
def share_email():
    try:
        recipient = request.form.get("recipient")
        image_url = request.form.get("image_url")
        filename = request.form.get("image_file")

        if not recipient:
            return jsonify({"status": "error", "message": "Missing data"}), 400

        if not image_url:
            if not filename:
                return jsonify({"status": "error", "message": "Missing image"}), 400
            image_url = url_for("serve_encoded", filename=filename)

        image_url = build_public_url(image_url)

        msg = Message(
            subject="StealthNet Classified Image",
            recipients=[recipient]
        )

        msg.body = f"""
STEALTHNET SECURE TRANSMISSION

Access your encoded image:
{image_url}

Use your secret key to extract the hidden message.
"""
        msg.html = f"""
<p><strong>STEALTHNET SECURE TRANSMISSION</strong></p>
<p>Access your encoded image:</p>
<p><a href="{image_url}">{image_url}</a></p>
<p>Use your secret key to extract the hidden message.</p>
"""

        mail.send(msg)

        log_activity(current_user.id, "Email Share")

        return jsonify({"status": "success"})

    except Exception as e:
        print("Mail Error:", e)
        return jsonify({"status": "error", "message": "Server error"}), 500

@app.route("/logs")
@login_required
def view_logs():
    if current_user.role != "admin":
        flash("Only admin can access logs.")
        return redirect(url_for("dashboard"))

    # Set number of days to keep logs
    LOG_RETENTION_DAYS = 1   # Change this to 1, 3, 7, 30 etc.

    expiry_time = datetime.datetime.utcnow() - datetime.timedelta(days=LOG_RETENTION_DAYS)

    # Delete old logs
    ActivityLog.query.filter(ActivityLog.timestamp < expiry_time).delete()
    db.session.commit()

    logs = ActivityLog.query.order_by(ActivityLog.timestamp.desc()).all()
    return render_template("logs.html", logs=logs)

with app.app_context():
   db.create_all()
   ensure_bootstrap_admin()


if __name__ == "__main__":
    app.run(debug=True)


