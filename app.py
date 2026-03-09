from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from PIL import Image
from werkzeug.utils import secure_filename
from sqlalchemy.exc import IntegrityError
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from werkzeug.middleware.proxy_fix import ProxyFix
import cloudinary
import cloudinary.uploader
import cloudinary.utils
import base64
import os
import re
import datetime
import json
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
import smtplib
from email.message import EmailMessage
from email.policy import SMTP
import time
import ssl
try:
    from dotenv import load_dotenv
except ImportError:
    def load_dotenv():
        return False

# ==============================
# APP CONFIGURATION
# ==============================

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "SUPER_SECRET_CLASSIFIED_KEY")
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///stealthnet.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config["UPLOAD_FOLDER"] = os.path.join(app.root_path, "uploads")
app.config["ENCODED_FOLDER"] = os.path.join(app.config["UPLOAD_FOLDER"], "encoded")
app.config["COMPRESSED_FOLDER"] = os.path.join(app.config["UPLOAD_FOLDER"], "compressed")

os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
os.makedirs(app.config["ENCODED_FOLDER"], exist_ok=True)
os.makedirs(app.config["COMPRESSED_FOLDER"], exist_ok=True)

ADMIN_BOOTSTRAP_USERNAME = os.environ.get("ADMIN_BOOTSTRAP_USERNAME", "ranjini")
ADMIN_BOOTSTRAP_PASSWORD = os.environ.get("ADMIN_BOOTSTRAP_PASSWORD", "ranjini!")
ADMIN_BOOTSTRAP_EMAIL = os.environ.get("ADMIN_BOOTSTRAP_EMAIL", "ranjini@stealthnet.local")

CLOUDINARY_CLOUD_NAME = os.environ.get("CLOUDINARY_CLOUD_NAME")
CLOUDINARY_API_KEY = os.environ.get("CLOUDINARY_API_KEY")
CLOUDINARY_API_SECRET = os.environ.get("CLOUDINARY_API_SECRET")
CLOUDINARY_FOLDER = os.environ.get("CLOUDINARY_FOLDER", "stealthnet")
COMPRESS_TARGET_KB = int(os.environ.get("COMPRESS_TARGET_KB", "50"))
COMPRESS_TARGET_BYTES = COMPRESS_TARGET_KB * 1024

CLOUDINARY_ENABLED = all([CLOUDINARY_CLOUD_NAME, CLOUDINARY_API_KEY, CLOUDINARY_API_SECRET])

if CLOUDINARY_ENABLED:
    cloudinary.config(
        cloud_name=CLOUDINARY_CLOUD_NAME,
        api_key=CLOUDINARY_API_KEY,
        api_secret=CLOUDINARY_API_SECRET,
        secure=True
    )

# -------- MAIL CONFIG --------
app.config['MAIL_SERVER'] = os.environ.get("MAIL_SERVER", "smtp.gmail.com")
app.config['MAIL_PORT'] = int(os.environ.get("MAIL_PORT", "587"))
app.config['MAIL_USE_TLS'] = os.environ.get("MAIL_USE_TLS", "true").lower() == "true"
app.config['MAIL_USERNAME'] = os.environ.get("MAIL_USERNAME", "")
app.config['MAIL_PASSWORD'] = os.environ.get("MAIL_PASSWORD", "")
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get("MAIL_DEFAULT_SENDER", app.config['MAIL_USERNAME'])
app.config['MAIL_TIMEOUT'] = int(os.environ.get("MAIL_TIMEOUT", "20"))
EMAIL_SEND_TIMEOUT_SECONDS = int(os.environ.get("EMAIL_SEND_TIMEOUT_SECONDS", "20"))

RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "").strip()
EMAIL_PROVIDER = os.environ.get("EMAIL_PROVIDER", "smtp").strip().lower()
if EMAIL_PROVIDER not in ("smtp", "resend"):
    EMAIL_PROVIDER = "smtp"
RESEND_FROM = os.environ.get("RESEND_FROM", "onboarding@resend.dev").strip()

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
    force_reset = os.environ.get("FORCE_ADMIN_PASSWORD_RESET", "false").lower() == "true"
    user = User.query.filter_by(username=ADMIN_BOOTSTRAP_USERNAME).first()
    hashed_password = bcrypt.generate_password_hash(ADMIN_BOOTSTRAP_PASSWORD).decode("utf-8")

    if user:
        user.role = "admin"
        if force_reset:
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

def build_download_url(image_url, filename):
    if not image_url:
        return image_url
    # For Cloudinary, force browser download with fl_attachment.
    if "res.cloudinary.com" in image_url and "/upload/" in image_url:
        return image_url.replace("/upload/", "/upload/fl_attachment/", 1)
    return image_url

def download_remote_file(remote_url, timeout_seconds=20):
    req = Request(
        remote_url,
        headers={"User-Agent": "StealthNet/1.0"}
    )
    with urlopen(req, timeout=timeout_seconds) as resp:
        return resp.read()

def compress_image_with_cloudinary(file_path, target_bytes):
    if not CLOUDINARY_ENABLED:
        raise ValueError("Cloudinary is not configured")

    upload_result = cloudinary.uploader.upload(
        file_path,
        folder=f"{CLOUDINARY_FOLDER}/compressor",
        resource_type="image"
    )
    public_id = upload_result.get("public_id")
    if not public_id:
        raise ValueError("Cloudinary upload failed")

    # Try progressively stronger compression until we reach target size.
    variants = [
        {"width": 1920, "quality": "auto:good"},
        {"width": 1600, "quality": "auto:good"},
        {"width": 1280, "quality": "auto:eco"},
        {"width": 1024, "quality": "auto:eco"},
        {"width": 900, "quality": 60},
        {"width": 800, "quality": 55},
        {"width": 720, "quality": 50},
        {"width": 640, "quality": 45},
        {"width": 560, "quality": 40},
        {"width": 480, "quality": 35},
    ]

    best_match = None
    for variant in variants:
        transformed_url, _ = cloudinary.utils.cloudinary_url(
            public_id,
            secure=True,
            resource_type="image",
            type="upload",
            transformation=[
                {"crop": "limit", "width": variant["width"]},
                {"fetch_format": "jpg", "quality": variant["quality"], "flags": "progressive"}
            ]
        )
        file_bytes = download_remote_file(transformed_url)
        current_size = len(file_bytes)

        if best_match is None or current_size < best_match["size"]:
            best_match = {
                "bytes": file_bytes,
                "size": current_size,
                "url": transformed_url
            }

        if current_size <= target_bytes:
            break

    if not best_match:
        raise ValueError("Could not generate compressed image")

    source_stem = os.path.splitext(os.path.basename(file_path))[0]
    output_filename = secure_filename(f"compressed_{int(time.time())}_{source_stem}.jpg")
    output_path = os.path.join(app.config["COMPRESSED_FOLDER"], output_filename)

    with open(output_path, "wb") as compressed_file:
        compressed_file.write(best_match["bytes"])

    return output_filename, best_match["url"], best_match["size"]

def send_classified_email(recipient, safe_filename, msg_data, msg_content_type, text_body, html_body, timeout_seconds):
    if EMAIL_PROVIDER == "resend":
        if not RESEND_API_KEY:
            raise ValueError("RESEND_API_KEY not configured")

        payload = {
            "from": RESEND_FROM,
            "to": [recipient],
            "subject": "StealthNet Classified Image",
            "text": text_body,
            "html": html_body,
            "attachments": [
                {
                    "filename": safe_filename,
                    "content": base64.b64encode(msg_data).decode("ascii")
                }
            ]
        }

        req = Request(
            "https://api.resend.com/emails",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {RESEND_API_KEY}",
                "Content-Type": "application/json"
            },
            method="POST"
        )

        try:
            with urlopen(req, timeout=timeout_seconds) as resp:
                if resp.status not in (200, 201, 202):
                    raise ValueError(f"Resend rejected request with status {resp.status}")
        except HTTPError as e:
            details = e.read().decode("utf-8", errors="ignore")
            raise ValueError(f"Resend HTTP error {e.code}: {details}") from e
        except URLError as e:
            raise ValueError(f"Resend network error: {e.reason}") from e
        return

    msg = EmailMessage()
    msg["Subject"] = "StealthNet Classified Image"
    msg["From"] = app.config["MAIL_DEFAULT_SENDER"]
    msg["To"] = recipient
    msg.set_content(text_body)
    maintype, subtype = msg_content_type.split("/", 1) if "/" in msg_content_type else ("application", "octet-stream")
    msg.add_attachment(msg_data, maintype=maintype, subtype=subtype, filename=safe_filename)

    smtp_host = app.config["MAIL_SERVER"]
    smtp_user = app.config["MAIL_USERNAME"]
    smtp_pass = app.config["MAIL_PASSWORD"]

    last_error = None
    last_stage = "init"
    for attempt in range(1, 4):
        server = None
        try:
            last_stage = "connect"
            server = smtplib.SMTP(smtp_host, app.config["MAIL_PORT"], timeout=timeout_seconds)
            last_stage = "ehlo-1"
            server.ehlo_or_helo_if_needed()
            last_stage = "starttls"
            server.starttls(context=ssl.create_default_context())
            last_stage = "ehlo-2"
            try:
                server.ehlo_or_helo_if_needed()
            except Exception:
                # Some SMTP relays drop post-TLS EHLO responses; continue to login.
                pass
            last_stage = "login"
            server.login(smtp_user, smtp_pass)
            last_stage = "send"
            raw_message = msg.as_bytes(policy=SMTP)
            server.sendmail(app.config["MAIL_DEFAULT_SENDER"], [recipient], raw_message)
            return
        except Exception as e:
            last_error = e
            time.sleep(1.0)
        finally:
            if server is not None:
                try:
                    server.quit()
                except Exception:
                    pass

    raise ValueError(f"SMTP send failed at '{last_stage}' (TLS587): {repr(last_error)}")

def send_share_email_job(recipient, safe_filename, user_id):
    msg_data = None
    msg_content_type = None

    encoded_path = os.path.join(app.config["ENCODED_FOLDER"], safe_filename) if safe_filename else ""
    if safe_filename and os.path.exists(encoded_path):
        file_size = os.path.getsize(encoded_path)
        # Keep comfortably below provider limits and unstable network failures.
        if file_size > 10 * 1024 * 1024:
            raise ValueError("Attachment too large. Use an image below 10MB.")
        with open(encoded_path, "rb") as image_fp:
            msg_data = image_fp.read()
        msg_content_type = "image/png" if safe_filename.lower().endswith(".png") else "application/octet-stream"

    if msg_data is None:
        raise ValueError("Encoded image attachment is required")

    text_body = f"""
STEALTHNET SECURE TRANSMISSION

Attached: encoded image file
Use your secret key to extract the hidden message from the attached image.
"""
    html_body = f"""
<p><strong>STEALTHNET SECURE TRANSMISSION</strong></p>
<p>Attached: encoded image file</p>
<p>Use your secret key to extract the hidden message from the attached image.</p>
"""

    send_classified_email(
        recipient=recipient,
        safe_filename=safe_filename,
        msg_data=msg_data,
        msg_content_type=msg_content_type,
        text_body=text_body,
        html_body=html_body,
        timeout_seconds=EMAIL_SEND_TIMEOUT_SECONDS
    )
    log_activity(user_id, "Email Share")

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

@app.route("/compress-image", methods=["GET", "POST"])
@login_required
def compress_image():
    if request.method == "POST":
        image = request.files.get("image")

        if not CLOUDINARY_ENABLED:
            flash("Cloudinary is not configured. Add credentials to use compressor.")
            return redirect(url_for("compress_image"))

        if not image or not image.filename:
            flash("Please select an image to compress.")
            return redirect(url_for("compress_image"))

        if not image.filename.lower().endswith((".png", ".jpg", ".jpeg", ".webp")):
            flash("Only PNG, JPG, JPEG, and WEBP formats are allowed.")
            return redirect(url_for("compress_image"))

        source_filename = secure_filename(image.filename)
        source_path = os.path.join(app.config["UPLOAD_FOLDER"], source_filename)
        image.save(source_path)

        try:
            compressed_file, _, compressed_size = compress_image_with_cloudinary(source_path, COMPRESS_TARGET_BYTES)
        except Exception as e:
            print("Compression Error:", e)
            flash("Compression failed. Please try another image.")
            return redirect(url_for("compress_image"))

        log_activity(current_user.id, "Compress Image")
        flash(f"Image compressed to {compressed_size / 1024:.1f} KB. Continue with Hide Message.")
        return redirect(url_for("embed", compressed_file=compressed_file))

    return render_template(
        "compress.html",
        cloudinary_enabled=CLOUDINARY_ENABLED,
        target_kb=COMPRESS_TARGET_KB
    )

@app.before_request
def redirect_legacy_static_encoded():
    legacy_prefix = "/static/encoded/"
    if request.path.startswith(legacy_prefix):
        legacy_filename = request.path[len(legacy_prefix):]
        return redirect(url_for("serve_encoded", filename=legacy_filename), code=302)

@app.after_request
def add_no_cache_headers(response):
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

@app.route("/encoded/<path:filename>")
def serve_encoded(filename):
    return send_from_directory(app.config["ENCODED_FOLDER"], filename, as_attachment=False)

# -------- EMBED --------
@app.route("/embed", methods=["GET", "POST"])
@login_required
def embed():
    compressed_file = secure_filename(request.values.get("compressed_file", "").strip())
    compressed_path = os.path.join(app.config["COMPRESSED_FOLDER"], compressed_file) if compressed_file else ""
    compressed_available = bool(compressed_file and os.path.exists(compressed_path))

    if request.method == "POST":
        image = request.files.get("image")
        secret = request.form.get("secret", "").strip()
        password = request.form.get("password", "").strip()
        redirect_target = url_for("embed", compressed_file=compressed_file) if compressed_available else url_for("embed")

        # Validate
        if not secret or not password:
            flash("All fields are required.")
            return redirect(redirect_target)

        if image and image.filename:
            if not image.filename.lower().endswith((".png", ".jpg", ".jpeg")):
                flash("Only PNG, JPG and JPEG formats are allowed.")
                return redirect(redirect_target)
            filename = secure_filename(image.filename)
            temp_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            image.save(temp_path)
        elif compressed_available:
            filename = compressed_file
            temp_path = compressed_path
        else:
            flash("Please upload an image first.")
            return redirect(redirect_target)

        encrypted_secret = encrypt_message(secret, password)

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
            image_url=image_url,
            download_url=build_download_url(image_url, output_filename)
        )

    return render_template("embed.html", compressed_file=compressed_file if compressed_available else "")
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

        if not recipient:
            return jsonify({"status": "error", "message": "Missing data"}), 400
        if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", recipient):
            return jsonify({"status": "error", "message": "Invalid email address"}), 400

        safe_filename = secure_filename(filename or "")

        if not safe_filename:
            return jsonify({"status": "error", "message": "Missing image attachment"}), 400

        send_share_email_job(recipient, safe_filename, current_user.id)
        return jsonify({"status": "success", "message": "Email sent successfully."})

    except Exception as e:
        print("Mail Error:", e)
        return jsonify({"status": "error", "message": str(e)}), 500

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
    app.run(debug=os.environ.get("FLASK_DEBUG", "true").lower() == "true")


