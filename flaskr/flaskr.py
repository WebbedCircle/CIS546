# all the imports
import os
import sqlite3
import json
from datetime import datetime
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, request, session, g, redirect, url_for, abort, \
     render_template, flash


app = Flask(__name__)  # create the application instance :)
app.config.from_object(__name__)  # load config from this file , flaskr.py

# Load default config and override config from an environment variable
app.config.update(dict(
    DATABASE=os.path.join(app.root_path, 'flaskr.db'),
    SECRET_KEY='development key',
    USERNAME='admin',
    PASSWORD='default'
))
app.config.from_envvar('FLASKR_SETTINGS', silent=True)


# Uploading images
UPLOAD_FOLDER = os.path.join(app.root_path, 'static/uploads')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Ensure upload directory exists
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def connect_db():
    """Connects to the specific database."""
    rv = sqlite3.connect(app.config['DATABASE'])
    rv.row_factory = sqlite3.Row
    return rv
    
def get_db():
    """Opens a new database connection if there is none yet for the
    current application context.
    """
    if not hasattr(g, 'sqlite_db'):
        g.sqlite_db = connect_db()
    return g.sqlite_db

@app.teardown_appcontext
def close_db(error):
    """Closes the database again at the end of the request."""
    if hasattr(g, 'sqlite_db'):
        g.sqlite_db.close()
        
def init_db():
    """Initializes the database."""
    with app.app_context():
        db = get_db()
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()

@app.cli.command('initdb')
def initdb_command():
    """Initializes the database."""
    init_db()
    print('Initialized the database.')

def format_file_size(file_path):
    """Formats the file size into a human-readable format (e.g., KB, MB)."""
    size = os.stat(file_path).st_size  # Get file size in bytes
    if size < 1024:
        return f"{size} bytes"
    elif size < 1048576:
        return f"{size / 1024:.2f} KB"
    elif size < 1073741824:
        return f"{size / 1048576:.2f} MB"
    else:
        return f"{size / 1073741824:.2f} GB"


def extract_metadata(image_path):
    """Extract EXIF metadata from an image."""
    metadata = {}
    try:
        img = Image.open(image_path)
        exif_data = img._getexif()
        if exif_data:
            for tag, value in exif_data.items():
                tag_name = TAGS.get(tag, tag)
                metadata[tag_name] = value

            # Extract GPS info if available
            if "GPSInfo" in metadata:
                gps_info = metadata["GPSInfo"]
                metadata["GPS"] = {GPSTAGS.get(t, t): gps_info[t] for t in gps_info}
                del metadata["GPSInfo"]
                
    except Exception as e:
        metadata["Error"] = str(e)
    
    return metadata


@app.route('/', methods=['GET', 'POST'])
def show_entries():
    # Get the username filter from the query parameters (if present)
    username_filter = request.args.get('username')
    
    db = get_db()
    
    # Modify the query based on whether we have a username filter
    if username_filter:
        cur = db.execute(
            'SELECT id, title, text, image_path, metadata, timestamp, username FROM entries WHERE username = ? ORDER BY id DESC',
            (username_filter,)
        )
    else:
        # No filter, show all entries
        cur = db.execute(
            'SELECT id, title, text, image_path, metadata, timestamp, username FROM entries ORDER BY id DESC'
        )
    
    entries = cur.fetchall()
    return render_template('show_entries.html', entries=entries)


@app.route('/add', methods=['POST'])
def add_entry():
    if not session.get('logged_in'):
        abort(401)
    db = get_db()
    title = request.form['title']
    text = request.form['text']
    image_path = None
    metadata = None
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    if 'image' in request.files:
        file = request.files['image']
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            image_path = f"/static/uploads/{filename}"
            
            # Extract Metadata
            metadata = extract_metadata(file_path)
            metadata['File Size'] = format_file_size(file_path)
            print(f"Extracted Metadata: {metadata}")
            
            # Additional file info
            metadata['file_name'] = filename
            metadata['file_size'] = os.path.getsize(file_path)
            image = Image.open(file_path)
            metadata['resolution'] = f"{image.width}x{image.height}"
    
    username = session.get('username')  # Get the logged-in username

    # Save entry with metadata, timestamp, and username
    db.execute(
        'INSERT INTO entries (title, text, image_path, metadata, timestamp, username) VALUES (?, ?, ?, ?, ?, ?)',
        (title, text, image_path, json.dumps(metadata) if metadata else None, timestamp, username)
    )
    db.commit()

    flash('New entry was successfully posted')
    return redirect(url_for('show_entries'))


@app.route('/metadata/<int:entry_id>')
def view_metadata(entry_id):
    db = get_db()
    cur = db.execute('SELECT title, image_path, metadata, username FROM entries WHERE id = ?', (entry_id,))
    entry = cur.fetchone()
    if entry is None:
        abort(404)
    
    metadata = json.loads(entry['metadata']) if entry['metadata'] else {}
    print(f"Metadata for entry {entry_id}: {metadata}")
    return render_template('metadata.html', entry=entry, metadata=metadata)


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    db = get_db()
    if request.method == 'POST':
        # Check the username
        cur = db.execute('SELECT password_hash FROM users WHERE username = ?', (request.form['username'],))
        user = cur.fetchone()
        # Validate user credentials
        if user is None:
            error = 'Invalid username'
        elif not check_password_hash(user['password_hash'], request.form['password']):
            error = 'Invalid password'
        else:
            session['logged_in'] = True
            session.permanent = True  # Ensure session persists
            session['username'] = request.form['username']  # Store the username in the session
            flash('You were logged in')
            return redirect(url_for('show_entries'))
    return render_template('login.html', error=error)


@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('username', None)  # Clear the username as well
    flash('You were logged out')
    return redirect(url_for('show_entries'))


@app.cli.command('initusers')
def init_users():
    db = get_db()
    db.execute("INSERT INTO users (username, password) VALUES (?, ?)", ('admin', 'default'))
    db.commit()
    print("Added admin user.")


@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    db = get_db()

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Check if username already exists
        cur = db.execute('SELECT id FROM users WHERE username = ?', (username,))
        if cur.fetchone():
            error = 'Username already taken.'
        else:
            db.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)',
                       (username, generate_password_hash(password)))
            db.commit()
            flash('Registration successful! You can now log in.')
            return redirect(url_for('login'))

    return render_template('register.html', error=error)


@app.route('/history')
def user_history():
    if not session.get('logged_in'):
        abort(401)
    
    username = session.get('username')
    db = get_db()
    cur = db.execute('SELECT id, title, text, image_path, metadata, timestamp FROM entries WHERE username = ? ORDER BY id DESC', (username,))
    entries = cur.fetchall()
    return render_template('show_entries.html', entries=entries)
