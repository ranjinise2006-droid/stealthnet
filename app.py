from flask import Flask, render_template, request, redirect, url_for, flash, send_file, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from PIL import Image
from werkzeug.utils import secure_filename
from flask_mail import Mail, Message
from sqlalchemy.exc import IntegrityError
from cryptography.fernet import Fernet
import base64
import hashlib
import os
import re
import datetime

# ==============================
# APP CONFIGURATION
# ==============================

app = Flask(__name__)
app.secret_key = "SUPER_SECRET_CLASSIFIED_KEY"

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///stealthnet.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

UPLOAD_FOLDER = "uploads"
ENCODED_FOLDER = "encoded"

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["ENCODED_FOLDER"] = ENCODED_FOLDER

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

# ==============================
# AES ENCRYPTION FUNCTIONS
# ==============================

def generate_key(password):
    key = hashlib.sha256(password.encode()).digest()
    return base64.urlsafe_b64encode(key)

def encrypt_message(message, password):
    key = generate_key(password)
    cipher = Fernet(key)
    return cipher.encrypt(message.encode()).decode()

def decrypt_message(encrypted_message, password):
    key = generate_key(password)
    cipher = Fernet(key)
    return cipher.decrypt(encrypted_message.encode()).decode()

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

DELIMITER = "<<<STEALTHNET>>>"

def encode_image(image_path, secret_message, password, output_path):
    image = Image.open(image_path).convert("RGB")
    encoded = image.copy()

    secret_message = secret_message.strip()
    password = password.strip()

    message = password + DELIMITER + secret_message
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

    binary_string = ''.join(data_bits)

    all_bytes = [binary_string[i:i+8] for i in range(0, len(binary_string), 8)]
    decoded = ''.join(chr(int(byte, 2)) for byte in all_bytes)

    parts = decoded.split(DELIMITER)

    if len(parts) < 2:
        return "INVALID_PASSWORD"

    extracted_password = parts[0].strip()
    encrypted_message = parts[1]

    if extracted_password == password.strip():
        return encrypted_message
    else:
        return "INVALID_PASSWORD"
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
            output_folder = os.path.join("static", "encoded")
            os.makedirs(output_folder, exist_ok=True)

            # Full output path
            output_path = os.path.join(output_folder, output_filename)

            # Encode image
            encode_image(png_path, encrypted_secret, password, output_path)

            # Log activity
            log_activity(current_user.id, "Embed Secret")

            return render_template("generated.html", image_file=output_filename)

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
        filename = request.form.get("image_file")

        if not recipient or not filename:
            return jsonify({"status": "error", "message": "Missing data"}), 400

        image_url = f"http://127.0.0.1:5000/static/encoded/{filename}"

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

        mail.send(msg)

        log_activity(current_user.id, "Email Share")

        return jsonify({"status": "success"})

    except Exception as e:
        print("Mail Error:", e)
        return jsonify({"status": "error", "message": "Server error"}), 500

@app.route("/logs")
@login_required
def view_logs():
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


if __name__ == "__main__":
    app.run(debug=True)