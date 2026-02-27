from flask import Flask, render_template, request, redirect, url_for, flash, send_file,jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from PIL import Image
from werkzeug.utils import secure_filename
from flask_mail import Mail,Message
from sqlalchemy.exc import IntegrityError
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
# DATABASE MODEL
# ==============================

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    login_attempts = db.Column(db.Integer, default=0)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

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

DELIMITER = "#####"

def encode_image(image_path, secret_message, password, output_path):
    image = Image.open(image_path)
    encoded = image.copy()

    message = password + DELIMITER + secret_message + DELIMITER
    binary_msg = ''.join(format(ord(i), '08b') for i in message)

    data_index = 0
    pixels = encoded.load()

    for y in range(encoded.height):
        for x in range(encoded.width):
            pixel = list(pixels[x, y])

            for n in range(3):
                if data_index < len(binary_msg):
                    pixel[n] = pixel[n] & ~1 | int(binary_msg[data_index])
                    data_index += 1

            pixels[x, y] = tuple(pixel)

    encoded.save(output_path)

def decode_image(image_path, password):
    image = Image.open(image_path)
    binary_data = ""
    pixels = image.load()

    for y in range(image.height):
        for x in range(image.width):
            for n in range(3):
                binary_data += str(pixels[x, y][n] & 1)

    all_bytes = [binary_data[i:i+8] for i in range(0, len(binary_data), 8)]

    decoded = ""
    delimiter_hits = 0

    for byte in all_bytes:
        if len(byte) < 8:
            continue

        decoded += chr(int(byte, 2))

        if decoded.count(DELIMITER) >= 2:
            break

    parts = decoded.split(DELIMITER)

    if len(parts) < 3:
        return "INVALID_PASSWORD"

    extracted_password = parts[0]
    secret_message = parts[1]

    if extracted_password == password:
        return secret_message
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

    new_user = User(
        username=username,
        email=email,
        password=hashed_password
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
            return redirect(url_for("dashboard"))
        else:
            if user:
                user.login_attempts += 1
                db.session.commit()

                if user.login_attempts >= 3:
                    flash("AI ALERT: Suspicious login activity detected.")

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
        secret = request.form["secret"]
        password = request.form["password"]

        if image:
            filename = secure_filename(image.filename)

            # Save temporary upload
            temp_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            image.save(temp_path)

            # Convert to PNG always
            img = Image.open(temp_path)
            png_filename = os.path.splitext(filename)[0] + ".png"
            png_path = os.path.join(app.config["UPLOAD_FOLDER"], png_filename)
            img.save(png_path, "PNG")

            output_filename = "encoded_" + png_filename
            output_path = os.path.join("static/encoded", output_filename)

            encode_image(png_path, secret, password, output_path)

            return render_template("generated.html",
                                   image_file=output_filename)

    return render_template("embed.html")
# -------- EXTRACT --------
@app.route('/extract', methods=['GET', 'POST'])
@login_required
def extract():
    if request.method == 'POST':
        image = request.files.get('image')
        password = request.form.get('password')

        if not image or not password:
            flash("All fields required.")
            return redirect(url_for('extract'))

        filename = secure_filename(image.filename)
        upload_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        image.save(upload_path)

        result = decode_image(upload_path, password)
        print("RESULT:",result)

        if result == "INVALID_PASSWORD":
            flash("Authentication Failed — Incorrect Extraction Key")
            return redirect(url_for('extract'))

        return render_template("result.html", secret=result)

    return render_template("extract.html")
# -------- LOGOUT --------

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("welcome"))

@app.route("/share-email", methods=["POST"])
@login_required
def share_email():
    try:
        recipient = request.form.get("recipient")
        filename = request.form.get("image_file")

        print("Recipient:", recipient)
        print("Filename:", filename)

        if not recipient or not filename:
            return jsonify({"status": "error", "message": "Missing data"}), 400

        image_url = f"https://stealthnet.onrender.com/static/encoded/{filename}"

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

        try:
            mail.send(msg)
            return jsonify({"status": "success"})
        except Exception as mail_error:
            print("Mail sending failed:", mail_error)
            return jsonify({"status": "error", "message": "Mail failed"}), 500

    except Exception as e:
        print("Route crashed:", e)
        return jsonify({"status": "error", "message": "Server error"}), 500
    
# ==============================
# MAIN
# ==============================

if __name__ == "__main__":
    with app.app_context():
        db.create_all()

    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000))
    )