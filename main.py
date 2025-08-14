from datetime import date, datetime
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
    text = db.Column(db.LargeBinary, nullable=False)
    date = db.Column(db.Date, server_default=func.current_date(), nullable=False)
    time = db.Column(db.Time, server_default=func.current_time(), nullable=False)

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
            new_user = User(username=user_name, email=email, password=password)
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('login'))
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
            login_user(user)
            return redirect(url_for('chat'))
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
        messages_for_view.append({
            "id": m.id,
            "username": m.author.username,
            "content": m.text,
            "created_at": created_at,
            "is_own": (m.user_id == current_user.id),
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
        plaintext = fernet.decrypt(m.text).decode("utf-8")  
        out.append({
            "id": m.id,
            "username": m.author.username,
            "content": plaintext,
            "created_at": created_at.isoformat(),
            "is_own": (m.user_id == current_user.id),
        })
    return jsonify(out)

@app.get("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == "__main__":
    app.config['DEBUG'] = True
    app.run(debug=True, port=5002)