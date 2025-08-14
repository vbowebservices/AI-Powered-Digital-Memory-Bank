import os
import re
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from sqlalchemy import or_

# ---------------- App Config ----------------
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///instance/memorybank.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')

db = SQLAlchemy(app)

# ---------------- Models ----------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

class Memory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    type = db.Column(db.String(10), nullable=False)  # text, image, video
    content = db.Column(db.Text)
    filepath = db.Column(db.String(255))
    date_created = db.Column(db.DateTime, default=datetime.utcnow)

# ---------------- Helpers ----------------
ALLOWED_EXTENSIONS = {
    'image': {'png', 'jpg', 'jpeg', 'gif'},
    'video': {'mp4', 'avi', 'mov', 'webm'}
}

def is_valid_email(email):
    pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    return re.match(pattern, email) is not None

def allowed_file(filename, mtype):
    if '.' not in filename:
        return False
    ext = filename.rsplit('.', 1)[1].lower()
    return ext in ALLOWED_EXTENSIONS.get(mtype, set())

# ---------------- Routes ----------------
@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()

        if not is_valid_email(email):
            flash('Invalid email format!', 'danger')
            return redirect(url_for('signup'))

        if User.query.filter_by(email=email).first():
            flash('Email already registered!', 'warning')
            return redirect(url_for('signup'))

        password_hash = generate_password_hash(password)
        new_user = User(email=email, password_hash=password_hash)
        db.session.add(new_user)
        db.session.commit()
        flash('Account created successfully. Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()

        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            flash('Welcome back!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password', 'danger')
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    query = Memory.query.filter_by(user_id=session['user_id'])

    search = request.args.get('search', '').strip()
    mtype = request.args.get('type', '')
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')

    if search:
        query = query.filter(or_(
            Memory.content.ilike(f"%{search}%"),
            Memory.filepath.ilike(f"%{search}%")
        ))
    if mtype in ['text', 'image', 'video']:
        query = query.filter_by(type=mtype)
    if start_date:
        try:
            query = query.filter(Memory.date_created >= datetime.strptime(start_date, '%Y-%m-%d'))
        except:
            pass
    if end_date:
        try:
            query = query.filter(Memory.date_created <= datetime.strptime(end_date, '%Y-%m-%d'))
        except:
            pass

    memories = query.order_by(Memory.date_created.desc()).all()
    return render_template('dashboard.html', memories=memories)

@app.route('/add_memory', methods=['GET', 'POST'])
def add_memory():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        mtype = request.form.get('type')
        content = request.form.get('content')
        file = request.files.get('file')

        filepath = None
        if file and file.filename != '':
            if not allowed_file(file.filename, mtype):
                flash(f'Invalid file type for {mtype}.', 'danger')
                return redirect(url_for('add_memory'))
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            filepath = filename

        new_memory = Memory(
            user_id=session['user_id'],
            type=mtype,
            content=content if mtype == 'text' else None,
            filepath=filepath
        )
        db.session.add(new_memory)
        db.session.commit()
        flash('Memory added successfully!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('memory_form.html')

@app.route('/memory/<int:id>')
def view_memory(id):
    mem = Memory.query.get_or_404(id)
    return render_template('memory_detail.html', memory=mem)

@app.route('/memory/<int:id>/delete', methods=['POST'])
def delete_memory(id):
    mem = Memory.query.get_or_404(id)
    db.session.delete(mem)
    db.session.commit()
    flash('Memory deleted.', 'info')
    return redirect(url_for('dashboard'))

# ---------------- Init ----------------
if __name__ == '__main__':
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    with app.app_context():
        db.create_all()
    app.run(debug=True)