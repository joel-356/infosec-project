from flask import Flask, render_template, request, redirect, session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import os
import re
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import base64
import mysql.connector
from mysql.connector import Error
from werkzeug.utils import secure_filename
from flask import send_from_directory, abort


app = Flask(__name__)
app.secret_key = "simple_secret_key"
KEY_FILE = "encryption.key"

UPLOAD_FOLDER = "uploads"
ALLOWED_EXTENSIONS = {"pdf", "png", "jpg", "jpeg", "txt"}

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024  # 5 MB limit

os.makedirs(UPLOAD_FOLDER, exist_ok=True)


# Initialize rate limiter
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
    strategy="fixed-window"
)

# MySQL Configuration
DB_CONFIG = {
    'host': '127.0.0.1',
    'port': 3307,
    'user': 'appuser',
    'password': 'apppassword',
    'database': 'message_app'
}

# Suspicious URL patterns and keywords
SUSPICIOUS_PATTERNS = [
    r'bit\.ly',
    r'tinyurl\.com',
    r'goo\.gl',
    r't\.co',
    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
    r'login.*\.com',
    r'verify.*account',
    r'update.*payment',
    r'suspended.*account',
    r'urgent.*action',
    r'click.*here.*now',
    r'confirm.*identity',
    r'security.*alert',
]

SUSPICIOUS_KEYWORDS = [
    'password', 'verify', 'suspended', 'urgent', 'click here',
    'confirm now', 'account locked', 'unusual activity', 'prize',
    'winner', 'claim', 'free money', 'act now', 'limited time'
]

EMAIL_ATTACK_PATTERNS = [
    r"(?is)<script.*?>",
    r"(?is)javascript:",
    r"(?is)onerror\s*=",
    r"(?is)onload\s*=",
    r"(?is)<iframe.*?>"
]

SENDER_FLAG_COUNT = {}
BLOCKED_EMAIL_SENDERS = set()

def log_email_intrusion(event_type, sender, detail):
    with open("email_ids.log", "a") as f:
        f.write(f"{datetime.now()} | {event_type} | sender={sender} | {detail}\n")

def detect_malicious_email_content(subject, message):
    combined = f"{subject} {message}"
    for pattern in EMAIL_ATTACK_PATTERNS:
        if re.search(pattern, combined):
            return True, pattern
    return False, None

def track_flagged_sender(sender):
    SENDER_FLAG_COUNT.setdefault(sender, 0)
    SENDER_FLAG_COUNT[sender] += 1
    if SENDER_FLAG_COUNT[sender] >= 3:
        BLOCKED_EMAIL_SENDERS.add(sender)
        return True
    return False


def get_db_connection():
    """Create and return a MySQL database connection"""
    try:
        connection = mysql.connector.connect(**DB_CONFIG)
        return connection
    except Error as e:
        print(f"Error connecting to MySQL: {e}")
        return None


def load_or_create_key():
    """Load encryption key from file or create new one"""
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            return f.read()
    else:
        password = "your_secure_password_here"  
        salt = get_random_bytes(32)
        key = PBKDF2(password, salt, dkLen=32)
        
        with open(KEY_FILE, "wb") as f:
            f.write(salt + key)
        return salt + key


def get_aes_key():
    """Extract the AES key from the stored data"""
    data = load_or_create_key()
    if len(data) == 64:  
        return data[32:]  
    return data[:32] 


AES_KEY = get_aes_key()


def pad(text):
    """Pad text to be multiple of 16 bytes (AES block size)"""
    padding_length = 16 - (len(text) % 16)
    return text + chr(padding_length) * padding_length


def unpad(text):
    """Remove padding from decrypted text"""
    padding_length = ord(text[-1])
    return text[:-padding_length]


def encrypt_text_aes(text):
    """Encrypt text using AES-256"""
    if text is None or text == "":
        return ""
    
    iv = get_random_bytes(16)
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
    
    padded_text = pad(text)
    encrypted = cipher.encrypt(padded_text.encode('utf-8'))
    
    result = base64.b64encode(iv + encrypted).decode('utf-8')
    return result


def decrypt_text_aes(encrypted_text):
    """Decrypt text using AES-256"""
    if encrypted_text is None or encrypted_text == "":
        return ""
    
    try:
        encrypted_data = base64.b64decode(encrypted_text)
        
        iv = encrypted_data[:16]
        encrypted_content = encrypted_data[16:]
        
        cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(encrypted_content).decode('utf-8')
        
        return unpad(decrypted)
    except Exception as e:
        print(f"Decryption error: {e}")
        return encrypted_text


def extract_urls(text):
    """Extract all URLs from text"""
    url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    return re.findall(url_pattern, text, re.IGNORECASE)


def check_suspicious_content(subject, message):
    """
    Check if email contains suspicious links or keywords
    Returns: (is_suspicious, reasons, suspicious_urls)
    """
    reasons = []
    suspicious_urls = []
    combined_text = f"{subject} {message}".lower()
    
    # Extract URLs
    urls = extract_urls(message)
    
    # Check each URL against suspicious patterns
    for url in urls:
        for pattern in SUSPICIOUS_PATTERNS:
            if re.search(pattern, url, re.IGNORECASE):
                suspicious_urls.append(url)
                reasons.append(f"Suspicious URL pattern detected: {url[:50]}...")
                break
    
    # Check for suspicious keywords
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword.lower() in combined_text:
            reasons.append(f"Suspicious keyword: '{keyword}'")
    
    # Check for multiple URLs (common in phishing)
    if len(urls) > 3:
        reasons.append(f"Contains {len(urls)} URLs (potential spam)")
    
    is_suspicious = len(reasons) > 0
    
    return is_suspicious, reasons, suspicious_urls


def user_exists(email):
    """Check if user exists in database"""
    connection = get_db_connection()
    if not connection:
        return False
    
    try:
        cursor = connection.cursor()
        cursor.execute("SELECT email FROM users WHERE email = %s", (email,))
        result = cursor.fetchone()
        return result is not None
    except Error as e:
        print(f"Error checking user: {e}")
        return False
    finally:
        cursor.close()
        connection.close()


def get_user_id():
    """Get user identifier for rate limiting (email if logged in, else IP)"""
    return session.get('user_email', get_remote_address())

def allowed_file(filename):
    return (
        "." in filename and
        filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
    )


@app.route("/", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def login():
    error = None

    if request.method == "POST":
        email = request.form["email"].strip()

        if user_exists(email):
            session["user_email"] = email
            return redirect("/dashboard")
        else:
            error = "Email not found."

    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.pop("user_email", None)
    return redirect("/")


@app.route("/dashboard")
@limiter.limit("30 per minute", key_func=get_user_id)
def dashboard():
    if "user_email" not in session:
        return redirect("/")

    connection = get_db_connection()
    if not connection:
        return "Database connection failed", 500
    
    try:
        cursor = connection.cursor(dictionary=True)

        # =======================
        # 1️⃣ Fetch ALL messages
        # =======================
        cursor.execute("""
            SELECT id, sender, receiver, subject, message, attachment,
                   DATE_FORMAT(timestamp, '%Y-%m-%d %H:%i') as timestamp,
                   is_flagged, flag_reasons, sender_ip
            FROM messages
            ORDER BY timestamp DESC
        """)
        messages = cursor.fetchall()
        
        safe_messages = []
        flagged_messages = []
        
        for msg in messages:
            decrypted_msg = {
                "id": msg["id"],
                "sender": msg["sender"],
                "receiver": msg["receiver"],
                "subject": decrypt_text_aes(msg["subject"]),
                "message": decrypt_text_aes(msg["message"]),
                "timestamp": msg["timestamp"],
                "is_flagged": msg["is_flagged"],
                "flag_reasons": msg["flag_reasons"].split('|') if msg["flag_reasons"] else [],
                "sender_ip": msg.get("sender_ip", "Unknown"),
                "attachment": msg["attachment"],
            }
            
            if decrypted_msg["is_flagged"]:
                flagged_messages.append(decrypted_msg)
            else:
                safe_messages.append(decrypted_msg)

        # =======================
        # 2️⃣ Fetch BLOCKED users
        # =======================
        cursor.execute("""
            SELECT email, blocked_emails_attempt, created_at
            FROM users
            WHERE email_disabled = TRUE
        """)
        blocked_users = cursor.fetchall()

        # =======================
        # 3️⃣ Render dashboard
        # =======================
        return render_template(
            "index.html",
            safe_messages=safe_messages,
            flagged_messages=flagged_messages,
            blocked_users=blocked_users,
            user=session["user_email"]
        )

    except Error as e:
        print(f"Error fetching dashboard data: {e}")
        return "Error fetching dashboard data", 500
    finally:
        cursor.close()
        connection.close()


@app.route("/my-inbox")
@limiter.limit("30 per minute", key_func=get_user_id)
def my_inbox():
    if "user_email" not in session:
        return redirect("/")

    user_email = session["user_email"]
    connection = get_db_connection()
    if not connection:
        return "Database connection failed", 500
    
    try:
        cursor = connection.cursor(dictionary=True)
        cursor.execute("""
            SELECT id, sender, receiver, subject, message,attachment,
                   DATE_FORMAT(timestamp, '%Y-%m-%d %H:%i') as timestamp,
                   is_flagged, flag_reasons, sender_ip
            FROM messages
            WHERE receiver = %s
            ORDER BY timestamp DESC
        """, (user_email,))
        messages = cursor.fetchall()
        
        decrypted_messages = []
        for msg in messages:
            decrypted_messages.append({
                "id": msg["id"],
                "sender": msg["sender"],
                "receiver": msg["receiver"],
                "subject": decrypt_text_aes(msg["subject"]),
                "message": decrypt_text_aes(msg["message"]),
                "timestamp": msg["timestamp"],
                "is_flagged": msg["is_flagged"],
                "flag_reasons": msg["flag_reasons"].split('|') if msg["flag_reasons"] else [],
                "sender_ip": msg.get("sender_ip", "Unknown"),
                "attachment": msg["attachment"]
            })
        
        return render_template(
            "my_inbox.html",
            messages=decrypted_messages,
            email=user_email
        )
    except Error as e:
        print(f"Error fetching inbox: {e}")
        return "Error fetching inbox", 500
    finally:
        cursor.close()
        connection.close()


@app.route("/send", methods=["GET", "POST"])
@limiter.limit("5 per minute", key_func=get_user_id)
def send():
    if "user_email" not in session:
        return redirect("/")

    sender = session["user_email"]
    error = None

    # Check if sender account is disabled
    connection = get_db_connection()
    if not connection:
        return "Database connection failed", 500

    try:
        cursor = connection.cursor(dictionary=True)
        cursor.execute(
            "SELECT blocked_emails_attempt, email_disabled FROM users WHERE email = %s",
            (sender,)
        )
        user_data = cursor.fetchone()
        if not user_data:
            return "User not found", 404
        if user_data["email_disabled"]:
            return render_template(
                "send.html",
                error="Your account has been disabled due to repeated blocked emails."
            )
    finally:
        cursor.close()
        connection.close()

    if request.method == "POST":
        receiver = request.form["receiver"].strip()
        subject = request.form["subject"]
        message = request.form["message"]
        attachment = request.files.get("attachment")

        sender_ip = request.headers.get(
            "X-Forwarded-For",
            request.remote_addr
        ).split(",")[0].strip()

        # Receiver check
        if not user_exists(receiver):
            return render_template("send.html", error="Receiver email does not exist.")

        # ===== IDS: text inspection =====
        is_suspicious, reasons, _ = check_suspicious_content(subject, message)

        malicious_detected, pattern = detect_malicious_email_content(subject, message)
        if malicious_detected:
            reasons.append(f"Malicious pattern detected: {pattern}")
            is_suspicious = True
            log_email_intrusion("IDS", sender, f"Pattern: {pattern}")

        # ===== Attachment handling =====
        attachment_name = None
        if attachment and attachment.filename:
            if not allowed_file(attachment.filename):
                return render_template(
                    "send.html",
                    error="Attachment type not allowed."
                )

            filename = secure_filename(attachment.filename)
            attachment_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            attachment.save(attachment_path)
            attachment_name = filename

        # ===== IPS: block malicious emails =====
        if is_suspicious:
            connection = get_db_connection()
            if connection:
                try:
                    cursor = connection.cursor()
                    cursor.execute("""
                        UPDATE users
                        SET blocked_emails_attempt = blocked_emails_attempt + 1
                        WHERE email = %s
                    """, (sender,))
                    connection.commit()

                    cursor.execute("""
                        SELECT blocked_emails_attempt FROM users WHERE email = %s
                    """, (sender,))
                    blocked_count = cursor.fetchone()[0]

                    if blocked_count >= 10:
                        cursor.execute("""
                            UPDATE users SET email_disabled = TRUE WHERE email = %s
                        """, (sender,))
                        connection.commit()
                        error = "Your account has been disabled due to repeated blocked emails."
                    else:
                        error = "Message blocked by security system."
                finally:
                    cursor.close()
                    connection.close()

            return render_template("send.html", error=error)

        # ===== Encrypt & store =====
        encrypted_subject = encrypt_text_aes(subject)
        encrypted_message = encrypt_text_aes(message)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M")

        connection = get_db_connection()
        if not connection:
            return "Database connection failed", 500

        try:
            cursor = connection.cursor()
            cursor.execute("""
                INSERT INTO messages
                (sender, receiver, subject, message, timestamp,
                 is_flagged, flag_reasons, sender_ip, attachment)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                sender,
                receiver,
                encrypted_subject,
                encrypted_message,
                timestamp,
                is_suspicious,
                '|'.join(reasons) if reasons else None,
                sender_ip,
                attachment_name
            ))
            connection.commit()
            return redirect("/dashboard")
        finally:
            cursor.close()
            connection.close()

    return render_template("send.html", error=error)



@app.route("/delete/<int:message_id>", methods=["POST"])
@limiter.limit("20 per minute", key_func=get_user_id)
def delete_message(message_id):
    if "user_email" not in session:
        return redirect("/")

    connection = get_db_connection()
    if not connection:
        return "Database connection failed", 500
    
    try:
        cursor = connection.cursor()
        cursor.execute("DELETE FROM messages WHERE id = %s", (message_id,))
        connection.commit()
        return redirect("/dashboard")
    except Error as e:
        print(f"Error deleting message: {e}")
        return "Error deleting message", 500
    finally:
        cursor.close()
        connection.close()

@app.route("/unblock-user/<email>", methods=["POST"])
def unblock_user_account(email):
    if "user_email" not in session:
        return redirect("/")

    connection = get_db_connection()
    if not connection:
        return "Database connection failed", 500

    try:
        cursor = connection.cursor()
        cursor.execute("""
            UPDATE users
            SET blocked_emails_attempt = 0,
                email_disabled = FALSE
            WHERE email = %s
        """, (email,))
        connection.commit()
    finally:
        cursor.close()
        connection.close()

    return redirect("/dashboard")

@app.route("/attachment/<int:message_id>")
def attachment(message_id):
    if "user_email" not in session:
        return redirect("/")

    connection = get_db_connection()
    if not connection:
        return "Database connection failed", 500

    try:
        cursor = connection.cursor(dictionary=True)
        cursor.execute("SELECT attachment FROM messages WHERE id = %s", (message_id,))
        row = cursor.fetchone()
        if not row or not row["attachment"]:
            abort(404)

        filename = row["attachment"]
        # Serve the file (inline, not forced download)
        return send_from_directory(app.config["UPLOAD_FOLDER"], filename)
    finally:
        cursor.close()
        connection.close()
        
@app.errorhandler(429)
def ratelimit_handler(e):
    return render_template('rate_limit.html', error=str(e.description)), 429


if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0')