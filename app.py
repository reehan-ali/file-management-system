import os
import io
import hashlib
from flask import Flask, render_template, request, redirect, url_for, flash, send_file, abort, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from cryptography.fernet import Fernet
import pyotp
from models import db, User, FileRecord, Share

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
INSTANCE_DIR = os.path.join(BASE_DIR, 'instance')
UPLOAD_DIR = os.path.join(INSTANCE_DIR, 'uploads')
KEY_PATH = os.path.join(INSTANCE_DIR, 'key.key')

MAX_UPLOAD_SIZE = 5 * 1024 * 1024  # 5 MB for demo
MALWARE_SIGNATURES = [b"EICAR", b"malware-demo-signature"]

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SFM_SECRET', 'dev-secret-key')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(INSTANCE_DIR, 'sfm.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# ensure paths
os.makedirs(UPLOAD_DIR, exist_ok=True)

# ensure key
if not os.path.exists(KEY_PATH):
    with open(KEY_PATH, 'wb') as kf:
        kf.write(Fernet.generate_key())

with open(KEY_PATH, 'rb') as kf:
    FERNET_KEY = kf.read()
fernet = Fernet(FERNET_KEY)

# init db and login
db.init_app(app)
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# human readable size filter
@app.template_filter('human_size')
def human_size(size):
    try:
        size = int(size)
    except Exception:
        return str(size)
    if size < 1024:
        return f"{size} B"
    for unit in ["KB", "MB", "GB", "TB"]:
        size = size / 1024.0
        if size < 1024:
            return f"{size:.1f} {unit}"
    return f"{size:.1f} PB"

def simple_malware_scan(data: bytes) -> bool:
    for sig in MALWARE_SIGNATURES:
        if sig in data:
            return True
    return False

def user_has_access(user, rec):
    if rec.owner_id == user.id:
        return True
    return Share.query.filter_by(file_id=rec.id, user_id=user.id).first() is not None

@app.before_first_request
def create_tables():
    db.create_all()

@app.route('/')
def index():
    return render_template('index.html')

# Register
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username','').strip()
        password = request.form.get('password','')
        if not username or not password:
            flash('Missing username or password')
            return redirect(url_for('register'))
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('register'))
        user = User(username=username, password_hash=generate_password_hash(password))
        db.session.add(user)
        db.session.commit()
        flash('Registered. Please log in.')
        return redirect(url_for('login'))
    return render_template('register.html')

# Login
@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username','')
        password = request.form.get('password','')
        user = User.query.filter_by(username=username).first()
        if not user or not check_password_hash(user.password_hash, password):
            flash('Invalid credentials')
            return redirect(url_for('login'))
        if user.totp_secret:
            token = request.form.get('token','').strip()
            if not token or not pyotp.TOTP(user.totp_secret).verify(token):
                flash('Invalid 2FA token')
                return redirect(url_for('login'))
        login_user(user)
        return redirect(url_for('dashboard'))
    return render_template('login.html')

# Logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# Dashboard with optional search query
@app.route('/dashboard')
@login_required
def dashboard():
    q = request.args.get('q','').strip()
    if q:
        my_files = FileRecord.query.filter(FileRecord.owner_id==current_user.id, FileRecord.filename.contains(q)).all()
        shared_rows = Share.query.filter_by(user_id=current_user.id).all()
        shared_files = [FileRecord.query.get(s.file_id) for s in shared_rows if q.lower() in (FileRecord.query.get(s.file_id).filename or '').lower()]
    else:
        my_files = FileRecord.query.filter_by(owner_id=current_user.id).all()
        shared_rows = Share.query.filter_by(user_id=current_user.id).all()
        shared_files = [FileRecord.query.get(s.file_id) for s in shared_rows]
    return render_template('dashboard.html', my_files=my_files, shared_files=shared_files, q=q)

# Upload (with description)
@app.route('/upload', methods=['GET','POST'])
@login_required
def upload():
    if request.method == 'POST':
        uploaded = request.files.get('file')
        description = request.form.get('description','').strip()
        if not uploaded:
            flash('No file provided')
            return redirect(url_for('upload'))
        filename = secure_filename(uploaded.filename)
        data = uploaded.stream.read(MAX_UPLOAD_SIZE + 1)
        if len(data) > MAX_UPLOAD_SIZE:
            flash('File too large')
            return redirect(url_for('upload'))
        if simple_malware_scan(data):
            flash('Malware detected — upload rejected')
            return redirect(url_for('upload'))
        encrypted = fernet.encrypt(data)
        stored_name = hashlib.sha256((filename + str(current_user.id) + os.urandom(8).hex()).encode()).hexdigest()
        path = os.path.join(UPLOAD_DIR, stored_name)
        with open(path, 'wb') as f:
            f.write(encrypted)
        rec = FileRecord(filename=filename, owner_id=current_user.id, stored_name=stored_name, size=len(data), file_metadata=description)
        db.session.add(rec)
        db.session.commit()
        flash('File uploaded and encrypted')
        return redirect(url_for('dashboard'))
    return render_template('upload.html')

# Download
@app.route('/download/<int:file_id>')
@login_required
def download(file_id):
    rec = FileRecord.query.get_or_404(file_id)
    if not user_has_access(current_user, rec):
        abort(403)
    path = os.path.join(UPLOAD_DIR, rec.stored_name)
    if not os.path.exists(path):
        abort(404)
    with open(path, 'rb') as f:
        encrypted = f.read()
    try:
        decrypted = fernet.decrypt(encrypted)
    except Exception:
        abort(500)
    return send_file(io.BytesIO(decrypted), download_name=rec.filename, as_attachment=True)

# Share
@app.route('/share', methods=['POST'])
@login_required
def share():
    file_id = int(request.form.get('file_id', 0))
    username = request.form.get('username','').strip()
    rec = FileRecord.query.get_or_404(file_id)
    if rec.owner_id != current_user.id:
        abort(403)
    user = User.query.filter_by(username=username).first()
    if not user:
        flash('No such user')
        return redirect(url_for('dashboard'))
    if Share.query.filter_by(file_id=rec.id, user_id=user.id).first():
        flash('Already shared')
        return redirect(url_for('dashboard'))
    s = Share(file_id=rec.id, user_id=user.id)
    db.session.add(s)
    db.session.commit()
    flash(f'File shared with {username}')
    return redirect(url_for('dashboard'))

# Edit metadata
@app.route('/edit_metadata', methods=['POST'])
@login_required
def edit_metadata():
    try:
        file_id = int(request.form.get('file_id', 0))
    except (TypeError, ValueError):
        flash('Invalid file id')
        return redirect(url_for('dashboard'))
    description = request.form.get('description','').strip()
    rec = FileRecord.query.get_or_404(file_id)
    if rec.owner_id != current_user.id:
        abort(403)
    rec.file_metadata = description
    db.session.commit()
    flash('Metadata updated')
    return redirect(url_for('dashboard'))

# Delete file
@app.route('/delete_file/<int:file_id>', methods=['POST'])
@login_required
def delete_file(file_id):
    rec = FileRecord.query.get_or_404(file_id)
    if rec.owner_id != current_user.id:
        abort(403)
    path = os.path.join(UPLOAD_DIR, rec.stored_name)
    if os.path.exists(path):
        try:
            os.remove(path)
        except Exception:
            pass
    Share.query.filter_by(file_id=rec.id).delete()
    db.session.delete(rec)
    db.session.commit()
    flash('File deleted')
    return redirect(url_for('dashboard'))

# Metadata JSON
@app.route('/metadata/<int:file_id>')
@login_required
def metadata(file_id):
    rec = FileRecord.query.get_or_404(file_id)
    if not user_has_access(current_user, rec):
        abort(403)
    return jsonify({
        'filename': rec.filename,
        'size': rec.size,
        'owner_id': rec.owner_id,
        'uploaded_at': rec.uploaded_at.isoformat() if rec.uploaded_at else None,
        'metadata': rec.file_metadata or ''
    })

# Profile (enable/disable 2FA)
@app.route('/profile', methods=['GET','POST'])
@login_required
def profile():
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'enable':
            secret = pyotp.random_base32()
            current_user.totp_secret = secret
            db.session.commit()
            otp_uri = pyotp.totp.TOTP(secret).provisioning_uri(name=current_user.username, issuer_name='SecureFileManager')
            flash('2FA enabled. Save secret (or provisioning URI) in your authenticator app.')
            return render_template('profile.html', otp_uri=otp_uri, secret=secret)
        elif action == 'disable':
            current_user.totp_secret = None
            db.session.commit()
            flash('2FA disabled')
            return redirect(url_for('profile'))
    return render_template('profile.html', otp_uri=None, secret=None)

if __name__ == '__main__':
    app.run(debug=True)
