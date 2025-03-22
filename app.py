from flask import Flask, request, render_template, send_from_directory, redirect, url_for, flash, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf.csrf import CSRFProtect
from flask import send_file
from io import BytesIO
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

# Ensure the SECRET_KEY is 32 bytes long (AES-256 requires a 32-byte key)
def ensure_key_length(key):
    if len(key) < 32:
        # Pad the key with zeros if it's too short
        return key.ljust(32, '\0')
    elif len(key) > 32:
        # Truncate the key if it's too long
        return key[:32]
    return key

# Encrypt data using AES-256
def encrypt_data(data, key):
    key = ensure_key_length(key)
    iv = os.urandom(16)  # Generate a random initialization vector (IV)
    cipher = Cipher(algorithms.AES(key.encode()), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data) + encryptor.finalize()
    return iv + encrypted_data  # Return IV + encrypted data

# Decrypt data using AES-256
def decrypt_data(encrypted_data, key):
    key = ensure_key_length(key)
    iv = encrypted_data[:16]  # Extract the IV from the beginning
    cipher = Cipher(algorithms.AES(key.encode()), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data[16:]) + decryptor.finalize()
    return decrypted_data
    
app = Flask(__name__)
@app.after_request
def remove_server_header(response):
    response.headers.pop('Server',None)
    return response
    
app.config['SECRET_KEY'] = 'your_secret_key_here'  # Required for Flask-Login and CSRF
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['UPLOAD_FOLDER'] = 'uploads'  # Folder to store uploaded images

# Initialize extensions
db = SQLAlchemy(app)
csrf = CSRFProtect(app)  # Enable CSRF protection
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Ensure the upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    directory = db.Column(db.String(120), nullable=False)  # New field for user directory

# Load user for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))  # Use Session.get() instead of Query.get()

# Helper function to check allowed file extensions
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'tiff'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Home route
@app.route('/')
@login_required
def home():
    # List images from the user's directory
    images = os.listdir(current_user.directory)
    return render_template('gallery.html', images=images)

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.password == password:
            login_user(user)
            flash(f'Welcome back, {username}!', 'success')
            return redirect(url_for('home'))
        flash('Invalid username or password. Please try again.', 'error')
    return render_template('login.html')

# Register route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if not User.query.filter_by(username=username).first():
            # Create a unique directory for the user
            user_directory = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(username))
            os.makedirs(user_directory, exist_ok=True)

            # Create the new user with their directory
            new_user = User(username=username, password=password, directory=user_directory)
            db.session.add(new_user)
            db.session.commit()

            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        flash('Username already exists. Please choose a different username.', 'error')
    return render_template('register.html')

# Logout route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('login'))

# Upload route
@app.route('/upload', methods=['POST'])
@login_required
def upload():
    if 'file' not in request.files:
        flash('No file part in the request.', 'error')
        return redirect(url_for('home'))

    file = request.files['file']
    if file.filename == '':
        flash('No file selected for upload.', 'error')
        return redirect(url_for('home'))

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file_data = file.read()  # Read the file data

        # Encrypt the file data
        encrypted_data = encrypt_data(file_data, app.config['SECRET_KEY'])

        # Save the encrypted file to the user's directory
        file_path = os.path.join(current_user.directory, filename)
        with open(file_path, 'wb') as f:
            f.write(encrypted_data)

        flash(f'Image "{filename}" uploaded successfully!', 'success')
    else:
        flash('Only image files are allowed (PNG, JPG, JPEG, GIF, TIFF).', 'error')

    return redirect(url_for('home'))

# Image Route
@app.route('/image/<filename>')
@login_required
def image(filename):
    file_path = os.path.join(current_user.directory, filename)
    if os.path.exists(file_path):
        # Read the encrypted file
        with open(file_path, 'rb') as f:
            encrypted_data = f.read()

        # Decrypt the file data
        decrypted_data = decrypt_data(encrypted_data, app.config['SECRET_KEY'])

        # Determine the MIME type based on the file extension
        mimetype = 'image/jpeg'  # Default to JPEG
        if filename.lower().endswith('.png'):
            mimetype = 'image/png'
        elif filename.lower().endswith('.gif'):
            mimetype = 'image/gif'
        elif filename.lower().endswith('.tiff'):
            mimetype = 'image/tiff'

        # Serve the decrypted image
        return send_file(BytesIO(decrypted_data), mimetype=mimetype)
    else:
        flash('File not found.', 'error')
        return redirect(url_for('home'))

# Delete images
@app.route('/delete/<filename>', methods=['POST'])
@login_required
def delete(filename):
    file_path = os.path.join(current_user.directory, filename)
    if os.path.exists(file_path):
        os.remove(file_path)
        flash(f'File "{filename}" deleted successfully.', 'success')
    else:
        flash('File not found. It may have already been deleted.', 'error')
    return redirect(url_for('home'))

# Initialize database
with app.app_context():
    db.create_all()

# Run the app
if __name__ == "__main__":
    app.run(host='192.167.1.4', port=5000, debug=True)
