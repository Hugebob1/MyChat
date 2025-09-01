import mimetypes
from datetime import date, datetime, timezone
import os
from flask import Flask, abort, render_template, redirect, url_for, flash, request, jsonify
from cryptography.fernet import Fernet
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user, login_required
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Text, select, ForeignKey, func
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from Mail import SendEmail
from Storage import Storage
from uuid import uuid4
from flask import send_from_directory

UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

load_dotenv()
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("FLASK_KEY")
fernet = Fernet(os.environ.get('MESSAGE_KEY'))

# CREATE DATABASE
class Base(DeclarativeBase):
    pass
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DB_URI", "sqlite:///users.db")
db = SQLAlchemy(model_class=Base)
db.init_app(app)

# Configure Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

s = Storage()
x = SendEmail()

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), unique=True, nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)

    messages = db.relationship(
        'Message',
        back_populates='author',
        cascade='all, delete-orphan'
    )

class Message(db.Model):
    __tablename__ = 'messages'
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.LargeBinary, nullable=True)
    date = db.Column(db.Date, server_default=func.current_date(), nullable=False)
    time = db.Column(db.Time, server_default=func.current_time(), nullable=False)
    file_path = db.Column(db.String(255), nullable=True)
    type = db.Column(db.String(20), nullable=False, default="text")
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)

    author = db.relationship('User', back_populates='messages')


with app.app_context():
    db.create_all()


#decorator for admin only
def admin_only(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if current_user.is_authenticated:
            if current_user.id != 1:
                abort(403)
        else:
            abort(403)
        return func(*args, **kwargs)
    return wrapper

def check_email(email):
    try:
        with open('valid_emails.txt', 'r', encoding='utf-8') as f:
            allowed = {line.strip().lower() for line in f if line.strip()}
        return email.lower() in allowed
    except FileNotFoundError:
        return False

@app.route('/register', methods=['GET', 'POST'])
def register():

    if request.method == 'POST':
        email = request.form['email']
        user_name = request.form.get("username")
        password = request.form.get("password")

        if check_email(email):
            test_user = User.query.filter_by(email=email).first()
            if test_user:
                flash('Email already registered, please log in!')
                return redirect(url_for('login'))
            password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)
            s.set_current_email(email)
            s.set_password(password)
            s.set_name(user_name)
            s.set_code()
            x.send_email(email, s.get_code())
            # new_user = User(username=user_name, email=email, password=password)
            # db.session.add(new_user)
            # db.session.commit()
            return redirect(url_for('verify'))
        else:
            flash('Your email is not allowed')
    return render_template("register.html")

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            s.set_current_email(user.email)
            s.set_code()
            x.send_email(email, s.get_code())
            return redirect(url_for('verify'))

        elif user:
            flash('Incorrect password')
        else:
            flash('Incorrect email')
    return render_template("login.html")

@app.route('/', methods=['GET', 'POST'])
def index():

    return render_template("index.html")

@app.route("/chat", methods=['GET', 'POST'])
@login_required
def chat():
    msgs = (
        db.session.query(Message)
        .join(User, Message.user_id == User.id)
        .order_by(Message.id.desc())
        .limit(100)
        .all()
    )
    msgs = list(reversed(msgs))

    messages_for_view = []
    for m in msgs:
        created_at = datetime.combine(m.date, m.time)
        if m.type == 'text':
            messages_for_view.append({
                "id": m.id,
                "username": m.author.username,
                "content": fernet.decrypt(m.text).decode("utf-8"),
                "created_at": created_at,
                "is_own": (m.user_id == current_user.id),
                "type": m.type,
            })
        else:
            messages_for_view.append({
                "id": m.id,
                "username": m.author.username,
                "content": m.file_path,
                "created_at": created_at,
                "is_own": (m.user_id == current_user.id),
                "type": m.type,
            })

    return render_template("mychat.html", messages=messages_for_view)

@app.post("/api/messages")
@login_required
def api_create_message():
    data = request.get_json() or {}
    text = (data.get("content") or "").strip()
    if not text:
        return jsonify({"error": "empty"}), 400

    cipher = fernet.encrypt(text.encode("utf-8"))   # bytes
    msg = Message(text=cipher, user_id=current_user.id)
    db.session.add(msg)
    db.session.commit()
    db.session.refresh(msg)

    created_at = datetime.combine(msg.date, msg.time)

    return jsonify({
        "id": msg.id,
        "username": current_user.username,
        "content": text,
        "created_at": created_at.isoformat(),
        "is_own": True,
        "type": msg.type
    }), 201

@app.get("/api/messages")
@login_required
def api_list_messages():
    before_id = request.args.get("before_id", type=int)
    q = db.session.query(Message).join(User, Message.user_id == User.id)
    if before_id:
        q = q.filter(Message.id < before_id)

    older = q.order_by(Message.id.desc()).limit(30).all()
    older.reverse()

    out = []
    for m in older:
        created_at = datetime.combine(m.date, m.time)

        if m.type == "text":
            content = fernet.decrypt(m.text).decode("utf-8") if m.text else ""
            msg_type = "text"

        elif m.type in ("image", "audio", "file"):
            content = m.file_path
            msg_type = m.type

        else:
            if m.file_path:
                path = m.file_path.lower()
                if path.endswith((".jpg", ".jpeg", ".png", ".gif")):
                    msg_type = "image"
                elif path.endswith((".mp3", ".wav", ".ogg", ".webm")):
                    msg_type = "audio"
                else:
                    msg_type = "file"
                content = m.file_path
            else:
                content = fernet.decrypt(m.text).decode("utf-8") if m.text else ""
                msg_type = "text"

        out.append({
            "id": m.id,
            "username": m.author.username,
            "content": content,
            "created_at": created_at.isoformat(),
            "is_own": (m.user_id == current_user.id),
            "type": msg_type,
        })

    return jsonify(out)




@app.route("/uploads/<path:filename>")
def uploaded_file(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)

@app.route("/api/messages/file", methods=["POST"])
@login_required
def upload_file():
    if "file" not in request.files:
        return {"error": "Brak pliku"}, 400

    file = request.files["file"]
    if not file or file.filename == "":
        return {"error": "Pusty plik"}, 400

    ext = (mimetypes.guess_extension(file.mimetype) or os.path.splitext(file.filename)[1] or ".bin").lower()
    if ext == ".jpe":
        ext = ".jpg"

    mime = (file.mimetype or "").lower()
    if mime.startswith("image/") or ext in (".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp"):
        msg_type = "image"
    elif mime.startswith("audio/") or ext in (".mp3", ".wav", ".ogg", ".webm", ".m4a"):
        msg_type = "audio"
    else:
        msg_type = "file"

    unique_name = f"{uuid4().hex}{ext}"
    abs_path = os.path.join(UPLOAD_FOLDER, unique_name)
    file.save(abs_path)

    file_url = f"/uploads/{unique_name}"
    new_msg = Message(text=None, user_id=current_user.id, type=msg_type, file_path=file_url)
    db.session.add(new_msg)
    db.session.commit()

    return {
        "id": new_msg.id,
        "username": current_user.username,
        "content": file_url,
        "type": msg_type,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "is_own": True,
        "file_path": new_msg.file_path,
    }


@app.get("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route("/verify", methods=['GET', 'POST'])
def verify():
    if request.method == "POST":
        code = (request.form.get("code") or "").strip()
        print(code)
        print(s.get_code())

        if s.get_code() != 0 and s.get_code()==int(code):
            if s.get_password()!="":
                new_user = User(username=s.get_name(), email=s.get_current_email(), password=s.get_password())
                db.session.add(new_user)
                db.session.commit()
                login_user(new_user)
                s.reset()
                return redirect(url_for('chat'))
            else:
                login_user(User.query.filter_by(email=s.get_current_email()).first())
                s.reset()
                return redirect(url_for('chat'))
        else:
            flash("Invalid code, try again")

    return render_template("verification.html")

if __name__ == "__main__":
    app.config['DEBUG'] = True
    app.run(debug=True, port=5002)