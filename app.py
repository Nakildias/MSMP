import os
import subprocess
import time
import signal
import mimetypes
import threading
import shutil
import json
import sys
import sqlite3
import tarfile
import random
import string
import psutil
from datetime import datetime
from functools import wraps
from pathlib import Path
from flask import (
    Flask, render_template, request, redirect, url_for,
    jsonify, flash, abort, Response, send_from_directory, session, g
)
from flask_socketio import SocketIO, emit
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

# --- Configuration ---
try:
    # Assume MINECRAFT_SERVER_PATH is defined as before
    MINECRAFT_SERVER_PATH = Path("./Minecraft_Server").resolve(strict=True)
except FileNotFoundError:
    print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
    print("!!! CRITICAL ERROR: MINECRAFT_SERVER_PATH does not exist !!!")
    print("!!! Please edit app.py and set the correct path.           !!!")
    print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
    exit(1)

SETTINGS_FILE = Path(__file__).parent / 'manager_settings.json'  # Stored outside server dir for security
SECRET_KEY_FILE = Path(__file__).parent / 'secret_key'

DEFAULT_SETTINGS = {
    "AUTOSTART_SERVER": False,
    "ENABLE_AUTO_RESTART_ON_CRASH": False,
    "ALLOW_REGISTRATION": True,
    "SERVER_JAR_NAME": "server.jar",
    "JAVA_EXECUTABLE": "java",
    "JAVA_RAM": "2G",
    "JAVA_CUSTOM_ARGS": "",
    "LOG_FILE_DISPLAY": str(MINECRAFT_SERVER_PATH / "logs" / "latest.log"),
    "DATABASE_DISPLAY": str(MINECRAFT_SERVER_PATH / 'users.db'),
    "MAX_LOG_LINES": 50,
    "ALLOWED_VIEW_EXTENSIONS": ['.txt', '.log', '.yml', '.yaml', '.json', '.properties', '.md'],
    "MAX_VIEW_FILE_SIZE_MB": 5,
    "ALLOWED_UPLOAD_EXTENSIONS": ['jar', 'zip', 'dat', 'json', 'yml', 'yaml', 'txt', 'conf', 'properties', 'schem', 'schematic', 'mcstructure', 'mcfunction', 'mcmeta', 'png', 'jpg', 'jpeg', 'gif'],
    "MAX_UPLOAD_SIZE_MB": 4096,
    "ALLOWED_EDIT_EXTENSIONS": ['.txt', '.yml', '.yaml', '.json', '.properties', '.conf', '.cfg'],
    "RESTART_DELAY_SECONDS": 5,
    "AUTO_BACKUP_ENABLED": False,
    "AUTO_BACKUP_INTERVAL_HOURS": 6,
    "BACKUP_RETENTION_COUNT": 10,
    # Branding settings
    "BRAND_NAME": "Nebula",
    "BRAND_COLOR": "#8b5cf6",  # violet-500
    "BRAND_ICON_URL": ""
}

DATABASE = Path(__file__).parent / 'users.db'  # Stored outside server dir for security
MONITOR_INTERVAL_SECONDS = 5
manager_settings = {}

# --- Functions to Load/Save JSON Settings ---
def load_settings():
    """Loads settings from JSON file or returns defaults."""
    global manager_settings # Ensure we modify the global variable
    try:
        if SETTINGS_FILE.is_file():
            with open(SETTINGS_FILE, 'r', encoding='utf-8') as f:
                loaded_settings = json.load(f)
                # Ensure all default keys are present, add if missing
                for key, default_value in DEFAULT_SETTINGS.items():
                    if key not in loaded_settings:
                        loaded_settings[key] = default_value
                manager_settings = loaded_settings
                print(f"Loaded settings from {SETTINGS_FILE}")
                return manager_settings # Return the loaded and potentially updated settings
        else:
            print(f"Settings file {SETTINGS_FILE} not found, using defaults.")
            manager_settings = DEFAULT_SETTINGS.copy() # Use a copy
            save_settings(manager_settings) # Create the file with defaults
            return manager_settings
    except (json.JSONDecodeError, IOError, Exception) as e:
        print(f"Error loading settings file {SETTINGS_FILE}: {e}. Using defaults.")
        manager_settings = DEFAULT_SETTINGS.copy() # Use defaults on error
        return manager_settings

def save_settings(settings_to_save):
    """Saves settings dictionary to JSON file."""
    try:
        with open(SETTINGS_FILE, 'w', encoding='utf-8') as f:
            json.dump(settings_to_save, f, indent=4) # Use indent for readability
        print(f"Saved settings to {SETTINGS_FILE}")
        return True
    except (IOError, Exception) as e:
        print(f"Error saving settings file {SETTINGS_FILE}: {e}")
        flash(f"Error saving manager settings: {e}", "error")
        return False

# --- Flask App Setup ---
def load_secret_key():
    """Loads secret key from file or generates/saves a new one."""
    if SECRET_KEY_FILE.exists():
        try:
            with open(SECRET_KEY_FILE, 'rb') as f:
                return f.read()
        except Exception as e:
            print(f"Error reading secret key: {e}")
    
    # Generate new if missing or error
    new_key = os.urandom(24)
    try:
        with open(SECRET_KEY_FILE, 'wb') as f:
            f.write(new_key)
        print(f"Generated new secret key at {SECRET_KEY_FILE}")
    except Exception as e:
        print(f"Error saving secret key: {e}")
    return new_key

app = Flask(__name__)
app.secret_key = load_secret_key()

# --- Socket.IO Setup ---
socketio = SocketIO(
    app, 
    cors_allowed_origins="*", 
    async_mode='eventlet',
    ping_timeout=60,      # How long to wait for pong response (seconds)
    ping_interval=25,     # How often to send ping (seconds) - keeps connection alive
    logger=False,         # Disable verbose logging
    engineio_logger=False # Disable engine.io logging
)

# Track last log position for real-time streaming
last_log_position = 0
last_log_content = ""

# --- Load Manager Settings AFTER app initialization ---
with app.app_context():
    load_settings()

# Update Flask config options
app.config['ALLOW_REGISTRATION'] = manager_settings.get('ALLOW_REGISTRATION', DEFAULT_SETTINGS['ALLOW_REGISTRATION'])
try:
    max_upload_mb = int(manager_settings.get('MAX_UPLOAD_SIZE_MB', DEFAULT_SETTINGS['MAX_UPLOAD_SIZE_MB']))
    app.config['MAX_CONTENT_LENGTH'] = max_upload_mb * 1024 * 1024
except ValueError:
    print(f"Warning: Invalid MAX_UPLOAD_SIZE_MB value '{manager_settings.get('MAX_UPLOAD_SIZE_MB')}'. Using default.")
    app.config['MAX_CONTENT_LENGTH'] = DEFAULT_SETTINGS['MAX_UPLOAD_SIZE_MB'] * 1024 * 1024

AUTOSTART_SERVER = manager_settings.get('AUTOSTART_SERVER', DEFAULT_SETTINGS['AUTOSTART_SERVER'])
ENABLE_AUTO_RESTART_ON_CRASH = manager_settings.get('ENABLE_AUTO_RESTART_ON_CRASH', DEFAULT_SETTINGS['ENABLE_AUTO_RESTART_ON_CRASH'])
SERVER_JAR_NAME = manager_settings.get('SERVER_JAR_NAME', DEFAULT_SETTINGS['SERVER_JAR_NAME'])
JAVA_EXECUTABLE = manager_settings.get('JAVA_EXECUTABLE', DEFAULT_SETTINGS['JAVA_EXECUTABLE'])
JAVA_RAM = manager_settings.get('JAVA_RAM', DEFAULT_SETTINGS['JAVA_RAM'])
JAVA_CUSTOM_ARGS = manager_settings.get('JAVA_CUSTOM_ARGS', DEFAULT_SETTINGS['JAVA_CUSTOM_ARGS'])
MAX_LOG_LINES = manager_settings.get('MAX_LOG_LINES', DEFAULT_SETTINGS['MAX_LOG_LINES'])
ALLOWED_VIEW_EXTENSIONS = set(manager_settings.get('ALLOWED_VIEW_EXTENSIONS', DEFAULT_SETTINGS['ALLOWED_VIEW_EXTENSIONS']))
MAX_VIEW_FILE_SIZE_MB = manager_settings.get('MAX_VIEW_FILE_SIZE_MB', DEFAULT_SETTINGS['MAX_VIEW_FILE_SIZE_MB'])
ALLOWED_UPLOAD_EXTENSIONS = set(manager_settings.get('ALLOWED_UPLOAD_EXTENSIONS', DEFAULT_SETTINGS['ALLOWED_UPLOAD_EXTENSIONS']))
ALLOWED_EDIT_EXTENSIONS = set(manager_settings.get('ALLOWED_EDIT_EXTENSIONS', DEFAULT_SETTINGS['ALLOWED_EDIT_EXTENSIONS']))
RESTART_DELAY_SECONDS = manager_settings.get('RESTART_DELAY_SECONDS', DEFAULT_SETTINGS['RESTART_DELAY_SECONDS'])
AUTO_BACKUP_ENABLED = manager_settings.get('AUTO_BACKUP_ENABLED', DEFAULT_SETTINGS['AUTO_BACKUP_ENABLED'])
AUTO_BACKUP_INTERVAL_HOURS = manager_settings.get('AUTO_BACKUP_INTERVAL_HOURS', DEFAULT_SETTINGS['AUTO_BACKUP_INTERVAL_HOURS'])
BACKUP_RETENTION_COUNT = manager_settings.get('BACKUP_RETENTION_COUNT', DEFAULT_SETTINGS['BACKUP_RETENTION_COUNT'])
LOG_FILE = MINECRAFT_SERVER_PATH / "logs" / "latest.log"
DATABASE = Path(__file__).parent / 'users.db'
BACKUPS_DIR = MINECRAFT_SERVER_PATH / 'Backups'

# --- Database Functions --- Added Section
def get_db():
    """Opens a new database connection if there is none yet for the current application context."""
    if 'db' not in g:
        g.db = sqlite3.connect(
            DATABASE,
            detect_types=sqlite3.PARSE_DECLTYPES
        )
        g.db.row_factory = sqlite3.Row # Return rows as dict-like objects
    return g.db

def get_java_args():
    """Build Java arguments from RAM setting and custom args."""
    ram = manager_settings.get('JAVA_RAM', DEFAULT_SETTINGS['JAVA_RAM'])
    custom_args = manager_settings.get('JAVA_CUSTOM_ARGS', '')
    
    args = [f"-Xmx{ram}", f"-Xms{ram}"]
    if custom_args and custom_args.strip():
        args.extend(custom_args.strip().split())
    return args

def create_backup():
    """Create a backup of the Minecraft server directory."""
    try:
        # Ensure backup directory exists
        BACKUPS_DIR.mkdir(parents=True, exist_ok=True)
        
        # Generate backup filename: backup-MM-DD-YY-N.tar.gz
        now = datetime.now()
        date_prefix = now.strftime("%m-%d-%y")
        
        # Find next backup number for today
        existing_backups = list(BACKUPS_DIR.glob(f"backup-{date_prefix}-*.tar.gz"))
        next_num = len(existing_backups) + 1
        
        backup_name = f"backup-{date_prefix}-{next_num}.tar.gz"
        backup_path = BACKUPS_DIR / backup_name
        
        print(f"Creating backup: {backup_path}")
        
        # Use system tar for non-blocking compression (offloads CPU work from Python process)
        try:
            # We explicitly exclude Backups dir itself and hidden files
            cmd = ["tar", "-czf", str(backup_path), "--exclude=./Backups", "--exclude=./.*", "."]
            
            # Using subprocess instead of tarfile python module prevents blocking the EventLoop/GIL
            subprocess.run(
                cmd,
                cwd=str(MINECRAFT_SERVER_PATH),
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
        except subprocess.CalledProcessError as e:
            return False, f"Tar command failed: {e.stderr.decode()}"
        except FileNotFoundError:
             print("System 'tar' command not found, falling back to Python tarfile (MAY BLOCK)...")
             with tarfile.open(backup_path, "w:gz") as tar:
                for item in MINECRAFT_SERVER_PATH.iterdir():
                    if item.name != 'Backups' and not item.name.startswith('.'):
                        tar.add(item, arcname=item.name)
        
        print(f"Backup created successfully: {backup_name}")
        
        # Clean up old backups if retention limit exceeded
        retention = int(manager_settings.get('BACKUP_RETENTION_COUNT', DEFAULT_SETTINGS['BACKUP_RETENTION_COUNT']))
        all_backups = sorted(BACKUPS_DIR.glob("backup-*.tar.gz"), key=lambda p: p.stat().st_mtime)
        while len(all_backups) > retention:
            oldest = all_backups.pop(0)
            oldest.unlink()
            print(f"Deleted old backup: {oldest.name}")
        
        return True, backup_name
    except Exception as e:
        print(f"Backup error: {e}")
        return False, str(e)

def backup_scheduler():
    """Background thread for scheduled backups."""
    global AUTO_BACKUP_ENABLED, AUTO_BACKUP_INTERVAL_HOURS
    while True:
        if AUTO_BACKUP_ENABLED:
            interval_seconds = AUTO_BACKUP_INTERVAL_HOURS * 3600
            time.sleep(interval_seconds)
            if AUTO_BACKUP_ENABLED:  # Check again after sleep
                print("Running scheduled backup...")
                create_backup()
        else:
            time.sleep(60)  # Check every minute if backups got enabled

# --- Function for Server Autostart ---
def try_start_server_on_launch():
    """Attempts to start the Minecraft server if not already running."""
    global server_process
    if is_server_running():
        print("Autostart Skipped: Server process appears to be running already.")
        return # Don't try to start if it's somehow already running

    server_jar_path = MINECRAFT_SERVER_PATH / SERVER_JAR_NAME
    if not server_jar_path.is_file():
        print(f"Autostart Error: Server JAR not found at: {server_jar_path}")
        return

    command = [JAVA_EXECUTABLE] + get_java_args() + ["-jar", str(server_jar_path), "nogui"]
    try:
        print(f"Autostart: Attempting server launch with command: {' '.join(command)}")
        print(f"Autostart: Working directory: {MINECRAFT_SERVER_PATH}")
        # Use os.setsid for process group separation on Unix-like systems
        preexec_fn = os.setsid if os.name != 'nt' else None
        server_process = subprocess.Popen(
            command,
            cwd=str(MINECRAFT_SERVER_PATH),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, # Capture stdout (useful for logs if needed, but primarily for process running)
            stderr=subprocess.PIPE, # Capture stderr for errors
            universal_newlines=True, # Decode streams as text
            encoding='utf-8',      # Specify encoding
            errors='replace',      # Handle potential encoding errors
            bufsize=1,             # Line buffered
            preexec_fn=preexec_fn  # Create new process group (Unix)
        )
        print(f"Autostart: Server process initiated with PID: {server_process.pid}")
        time.sleep(2) # Give it a moment to potentially fail
        if server_process.poll() is not None:
             # Try reading stderr if the process died quickly
             stderr_output = "N/A"
             try:
                 stderr_output = server_process.stderr.read()
             except Exception:
                 pass # Ignore errors reading stderr if it's already closed
             print(f"Autostart Error: Server process terminated quickly after launch.")
             print(f"Autostart Exit Code: {server_process.returncode}")
             print(f"Autostart Stderr (if available): {stderr_output[:500]}...") # Print first 500 chars
             server_process = None # Reset process variable as it's dead
        else:
            print("Autostart: Server launch sequence initiated successfully.")

    except FileNotFoundError:
        print(f"Autostart Error: '{JAVA_EXECUTABLE}' command not found. Is Java installed and in PATH?")
        server_process = None
    except Exception as e:
        print(f"Autostart Error: Failed to start server: {e}")
        server_process = None
# --- End of Autostart Function ---

@app.teardown_appcontext
def close_connection(exception):
    """Closes the database again at the end of the request."""
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    """Initializes the database and creates tables if they don't exist."""
    db = get_db()
    cursor = db.cursor()
    cursor.execute(
        '''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
        '''
    )
    db.commit()
    print("Database initialized.")

@app.cli.command('init-db')
def init_db_command():
    """Clear existing data and create new tables."""
    init_db()
    print('Initialized the database.')

# Initialize DB before the first request if needed (optional, can use flask init-db command)
# Consider using Flask's built-in command `flask init-db` instead for better practice
try:
    with app.app_context():
        init_db()
except Exception as e:
    print(f"Could not initialize database automatically: {e}")
    print("Run 'flask init-db' command manually if the table doesn't exist.")


# --- Global Variables for Server Process and State ---
server_process = None
user_initiated_stop = False
server_management_lock = threading.Lock()

# --- Authentication Decorator and Helpers --- Added Section
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if g.user is None:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

@app.before_request
def load_logged_in_user():
    """If a user id is stored in the session, load the user object from the database into ``g.user``."""
    user_id = session.get('user_id')
    if user_id is None:
        g.user = None
    else:
        db = get_db()
        g.user = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()

@app.context_processor
def inject_user():
    """Inject user and branding variables into templates"""
    icon_path = Path(__file__).parent / 'static' / 'icon.png'
    return dict(
        user=g.user,
        brand_name=manager_settings.get('BRAND_NAME', DEFAULT_SETTINGS['BRAND_NAME']),
        brand_color=manager_settings.get('BRAND_COLOR', DEFAULT_SETTINGS['BRAND_COLOR']),
        has_custom_icon=icon_path.exists()
    )

# --- Helper Functions ---

def is_server_running():
    """Checks if the server process is active (thread-safe)."""
    global server_process
    with server_management_lock:
        # Check if process exists and hasn't terminated
        is_running = server_process and server_process.poll() is None
        if server_process and not is_running and user_initiated_stop:
             print("is_server_running check: Detected server stopped (user initiated). Clearing process handle.")
             server_process = None # Clear handle if stopped and user intended it
             is_running = False
    return is_running

def get_latest_logs(num_lines=MAX_LOG_LINES):
    """Reads the last N lines from the log file."""
    try:
        if not LOG_FILE.is_file():
            return ["Log file not found or server hasn't started yet."]
        with open(LOG_FILE, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
            return lines[-num_lines:]
    except Exception as e:
        print(f"Error reading log file: {e}")
        return [f"Error reading log file: {e}"]

def is_safe_path(requested_path, base_path=MINECRAFT_SERVER_PATH):
    """Security check: Ensure requested_path is within the base_path."""
    try:
        base_resolved = base_path.resolve(strict=True)
        if not base_resolved.is_dir(): return False
        req_resolved = requested_path.resolve(strict=False)
    except (FileNotFoundError, NotADirectoryError): return False
    except Exception as e: print(f"Path resolution error in is_safe_path: {e}"); return False
    try:
        if hasattr(Path, 'is_relative_to'): return req_resolved.is_relative_to(base_resolved)
        else:
             if base_resolved.drive != req_resolved.drive: return False
             return base_resolved == Path(os.path.commonpath([base_resolved, req_resolved]))
    except ValueError: return False
    except Exception as e: print(f"Path comparison error in is_safe_path: {e}"); return False

def get_full_path(relative_subpath):
    """Constructs and validates a full path from a relative subpath string."""
    if not relative_subpath or Path(relative_subpath).is_absolute(): return None
    full_path = MINECRAFT_SERVER_PATH / Path(relative_subpath)
    if not is_safe_path(full_path):
        print(f"!!! SECURITY ALERT: Attempt to access unsafe path '{full_path}' derived from '{relative_subpath}'")
        return None
    return full_path # MINECRAFT_SERVER_PATH / Path(relative_subpath)

def allowed_file(filename):
    """Checks if the uploaded file extension is allowed."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_UPLOAD_EXTENSIONS

def get_parent_rel_path(rel_path_str):
     """Gets the relative path string of the parent directory."""
     if not rel_path_str: return None
     path_obj = Path(rel_path_str)
     parent = path_obj.parent
     if parent == Path('.'): return ''
     else: return str(parent)

def render_file_error(message, category="error", suggest_parent_path=None, is_root=False):
    """Helper to flash msg & render error page or redirect."""
    flash(message, category)
    # Ensure redirection happens correctly even if suggest_parent_path is empty string (root)
    if suggest_parent_path is not None and not is_root:
         return redirect(url_for('files', subpath=suggest_parent_path))
    # Redirect to root if it's a root error or no parent suggested
    elif is_root or suggest_parent_path is None:
         return redirect(url_for('files')) # Redirect to root file browser on error
    else: # Should ideally not be reached if logic above is correct
         return render_template("file_error.html", error_message=message)


def is_htmx_request():
    """Check if the current request is an HTMX request."""
    return request.headers.get('HX-Request') == 'true'


def render_spa(template_name, **context):
    """Render template with SPA support. Returns partial for HTMX, full for normal."""
    # Add common context
    context['brand_name'] = manager_settings.get('BRAND_NAME', DEFAULT_SETTINGS['BRAND_NAME'])
    context['brand_color'] = manager_settings.get('BRAND_COLOR', DEFAULT_SETTINGS['BRAND_COLOR'])
    context['has_custom_icon'] = (Path(__file__).parent / 'static' / 'icon.png').exists()
    context['status'] = "Running" if is_server_running() else "Stopped"
    
    if is_htmx_request():
        # For HTMX requests, return just the content block
        return render_template(template_name, **context)
    else:
        # For full page loads, wrap in base template
        return render_template(template_name, **context)

@app.template_filter('basename')
def basename_filter(s):
    if s: return os.path.basename(s)
    return ''

@app.template_filter('dirname')
def dirname_filter(s):
    if s: return str(Path(s).parent)
    return ''

# --- Authentication Routes ---

@app.route('/register', methods=('GET', 'POST'))
def register():
    if not app.config['ALLOW_REGISTRATION']:
        flash('User registration is currently disabled.', 'warning')
        return redirect(url_for('login'))
    # --------------------

    if g.user: # If already logged in, redirect to index
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None

        if not username:
            error = 'Username is required.'
        elif not password:
            error = 'Password is required.'
        else:
            user = db.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
            if user is not None:
                error = f"User {username} is already registered."

        if error is None:
            try:
                db.execute(
                    'INSERT INTO users (username, password_hash) VALUES (?, ?)',
                    (username, generate_password_hash(password))
                )
                db.commit()
            except sqlite3.IntegrityError:
                 error = f"User {username} is already registered."
            except Exception as e:
                error = f"Database error: {e}"
            else:
                flash('Registration successful! Please log in.', 'success')
                return redirect(url_for('login'))

        flash(error, 'error')

    # Render the registration template for GET requests or if POST failed
    return render_template('register.html')


@app.route('/login', methods=('GET', 'POST'))
def login():
    if g.user: # If already logged in, redirect to index
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()

        if user is None:
            error = 'Incorrect username.'
        elif not check_password_hash(user['password_hash'], password):
            error = 'Incorrect password.'

        if error is None:
            # Store the user id in a new session and return to the index
            session.clear()
            session['user_id'] = user['id']
            flash(f'Welcome back, {user["username"]}!', 'success')
            # Redirect to the originally requested page or index
            next_url = request.form.get('next') or url_for('index')
            return redirect(next_url)

        flash(error, 'error')

    return render_template('login.html')


@app.route('/logout')
def logout():
    """Clear the current session, including the stored user id."""
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

def _start_server_process():
    """
    Internal function to launch the Minecraft server subprocess.
    Assumes lock is NOT held by caller. Manages globals directly.
    Returns True on successful launch attempt, False otherwise.
    """
    global server_process, user_initiated_stop

    # Double-check if already running (could happen in race condition before lock)
    with server_management_lock:
        if server_process and server_process.poll() is None:
            print("_start_server_process: Server already running, skipping.")
            return True # Already running is considered a success state

    server_jar_path = MINECRAFT_SERVER_PATH / SERVER_JAR_NAME
    if not server_jar_path.is_file():
        print(f"_start_server_process Error: Server JAR not found at: {server_jar_path}")
        # No flash here as this is internal, caller should handle UI feedback
        return False

    command = [JAVA_EXECUTABLE] + get_java_args() + ["-jar", str(server_jar_path), "nogui"]
    new_process = None
    try:
        print(f"_start_server_process: Starting server with command: {' '.join(command)}")
        print(f"_start_server_process: Working directory: {MINECRAFT_SERVER_PATH}")
        # Use os.setsid for process group separation on Unix-like systems
        # This helps ensure termination kills the whole Java process tree later
        preexec_fn = os.setsid if os.name != 'nt' else None
        new_process = subprocess.Popen(
            command,
            cwd=str(MINECRAFT_SERVER_PATH),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, # Capture stdout (useful for logs if needed, but primarily for process running)
            stderr=subprocess.PIPE, # Capture stderr for errors
            universal_newlines=True, # Decode streams as text
            encoding='utf-8',        # Specify encoding
            errors='replace',        # Handle potential encoding errors
            bufsize=1,               # Line buffered
            preexec_fn=preexec_fn    # Create new process group (Unix)
        )
        print(f"_start_server_process: Server process initiated with PID: {new_process.pid}")

        # Short delay to check for immediate crash
        time.sleep(2)
        if new_process.poll() is not None:
            # Process died quickly
            stderr_output = "N/A"
            try: stderr_output = new_process.stderr.read() # Read captured error output
            except Exception: pass # Ignore errors reading stderr if it's already closed

            print(f"_start_server_process Error: Server process terminated quickly after launch.")
            print(f"_start_server_process Exit Code: {new_process.returncode}")
            print(f"_start_server_process Stderr (if available): {stderr_output[:500]}...") # Print first 500 chars
            # No flash here, caller handles UI
            return False
        else:
            # Launch seems successful, update global state under lock
            with server_management_lock:
                server_process = new_process
                user_initiated_stop = False # Reset flag on successful start
            print("_start_server_process: Server launch sequence initiated successfully.")
            return True

    except FileNotFoundError:
        print(f"_start_server_process Error: '{JAVA_EXECUTABLE}' command not found. Is Java installed and in PATH?")
        # No flash here
        return False
    except Exception as e:
        print(f"_start_server_process Error: Failed to start server process: {e}")
        # No flash here
        # Clean up if Popen partially succeeded but threw error later
        if new_process and new_process.poll() is None:
             try: new_process.kill(); new_process.wait(timeout=5)
             except: pass
        return False

def parse_properties(file_path):
    """Parses a .properties file into a list of dictionaries (for order/comments)"""
    settings = []
    if not file_path.is_file():
        return settings # Return empty list if file doesn't exist
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                stripped_line = line.strip()
                if not stripped_line: # Keep empty lines for spacing
                     settings.append({'type': 'empty', 'raw': line})
                elif stripped_line.startswith('#'): # Keep comments
                    settings.append({'type': 'comment', 'raw': line})
                elif '=' in stripped_line:
                    key, value = stripped_line.split('=', 1)
                    settings.append({'type': 'setting', 'key': key.strip(), 'value': value.strip(), 'raw': line})
                else: # Keep unexpected lines as raw
                     settings.append({'type': 'unknown', 'raw': line})
        return settings
    except Exception as e:
        print(f"Error parsing properties file {file_path}: {e}")
        flash(f"Error reading properties file: {e}", "error")
        return [] # Return empty on error

def save_properties(file_path, settings_dict):
    """Saves settings back to a .properties file, attempting to preserve comments/order"""
    original_settings_list = parse_properties(file_path)
    if not original_settings_list and file_path.exists():
         # If parsing failed but file exists, indicates read error
         raise IOError(f"Failed to read original properties file {file_path} for saving.")
    elif not file_path.exists():
         # Handle case where file might not exist yet (e.g., first setup)
         pass # Or create a default structure

    try:
        with open(file_path, 'w', encoding='utf-8') as f:
             for item in original_settings_list:
                 if item['type'] == 'setting':
                     key = item['key']
                     # Update value if it was submitted in the form, otherwise keep original
                     new_value = settings_dict.get(key, item['value'])
                     f.write(f"{key}={new_value}\n")
                 else:
                     # Write back comments, empty lines, or unknown lines as they were
                     f.write(item['raw'])
    except Exception as e:
         print(f"Error writing properties file {file_path}: {e}")
         raise IOError(f"Error writing properties file: {e}") # Re-raise to be caught by route

# --- Server Control Routes --- (Apply @login_required)
@app.route('/server_settings', methods=['GET', 'POST'])
@login_required
def server_settings():
    global manager_settings # Allow modification
    if request.method == 'POST':
        # Create a copy to modify safely
        updated_settings = manager_settings.copy()
        form_errors = []

        # Process each setting from the form
        for key in DEFAULT_SETTINGS.keys():
            # Skip derived display paths
            if key in ["LOG_FILE_DISPLAY", "DATABASE_DISPLAY"]:
                continue

            form_value = request.form.get(key)

            form_value = request.form.get(key)

            # Handle checkboxes (booleans) - value is 'on' if checked, None otherwise
            # Note: This assumes all boolean settings ARE present in the form. 
            # If a boolean setting is missing from the form, it will be disabled (set to False).
            if isinstance(DEFAULT_SETTINGS[key], bool):
                updated_settings[key] = (form_value == 'on')

            # Handle numbers (int/float)
            elif isinstance(DEFAULT_SETTINGS[key], int):
                if form_value is not None:
                    try:
                        updated_settings[key] = int(form_value)
                    except (ValueError, TypeError):
                        form_errors.append(f"Invalid integer value for {key}: '{form_value}'")

            elif isinstance(DEFAULT_SETTINGS[key], float):
                if form_value is not None:
                    try:
                        updated_settings[key] = float(form_value)
                    except (ValueError, TypeError):
                        form_errors.append(f"Invalid float value for {key}: '{form_value}'")

            # Handle lists/sets (expect comma-separated string from textarea/input)
            elif isinstance(DEFAULT_SETTINGS[key], list) or isinstance(DEFAULT_SETTINGS[key], set):
                 if form_value is not None:
                     # Split by comma, strip whitespace from each item, remove empty strings
                     items = [item.strip() for item in form_value.split(',') if item.strip()]
                     # Keep as list (JSON serializable)
                     updated_settings[key] = items
                 
            # Handle strings (default case)
            else:
                if form_value is not None:
                    updated_settings[key] = form_value

        # --- Security Verification for Enabling Registration ---
        current_allow_reg = manager_settings.get('ALLOW_REGISTRATION', DEFAULT_SETTINGS['ALLOW_REGISTRATION'])
        new_allow_reg = updated_settings.get('ALLOW_REGISTRATION', False)
        
        # If trying to ENABLE registration (False -> True)
        if new_allow_reg and not current_allow_reg:
            otp_input = request.form.get('otp_code')
            session_otp = session.get('registration_otp')
            
            if otp_input and session_otp and otp_input == session_otp:
                # OTP is correct, clear it and proceed
                session.pop('registration_otp', None)
            else:
                # OTP missing or invalid
                if not session_otp:
                    # Generate new OTP
                    session_otp = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
                    session['registration_otp'] = session_otp
                    print(f"\n{'='*40}\n[SECURITY ALERT] Registration Enable Attempt\nVerification Code: {session_otp}\n{'='*40}\n")
                    flash("Security check required. A verification code has been sent to the server console.", "warning")
                elif otp_input:
                    flash("Invalid verification code. Please check the server console.", "error")
                
                # Halt save and show OTP modal
                # Pass back the form data so user doesn't lose other changes
                icon_path = Path(__file__).parent / 'static' / 'icon.png'
                return render_template('server_settings.html', 
                                     settings=updated_settings, 
                                     default_settings=DEFAULT_SETTINGS,
                                     otp_modal=True,
                                     icon_exists=icon_path.exists(),
                                     icon_mtime=int(icon_path.stat().st_mtime) if icon_path.exists() else 0)
        # -------------------------------------------------------

        if form_errors:
            for error in form_errors:
                flash(error, "error")
        else:
            # Update the derived display paths before saving/applying
            updated_settings["LOG_FILE_DISPLAY"] = str(MINECRAFT_SERVER_PATH / "logs" / "latest.log")
            updated_settings["DATABASE_DISPLAY"] = str(MINECRAFT_SERVER_PATH / 'users.db')

            if save_settings(updated_settings):
                flash("Manager settings saved successfully. A restart of the manager application is required for some settings (like Java args or paths) to take full effect.", "success")
                # *** CRITICAL: Apply the settings immediately where possible ***
                # This requires reloading the global Python variables and Flask config
                # Ideally, this logic should be centralized. For now, duplicate the applying logic:
                app.config['ALLOW_REGISTRATION'] = updated_settings.get('ALLOW_REGISTRATION', DEFAULT_SETTINGS['ALLOW_REGISTRATION'])
                try:
                    max_upload_mb = int(updated_settings.get('MAX_UPLOAD_SIZE_MB', DEFAULT_SETTINGS['MAX_UPLOAD_SIZE_MB']))
                    app.config['MAX_CONTENT_LENGTH'] = max_upload_mb * 1024 * 1024
                except ValueError: pass # Already flashed error

                # Update global Python variables (again, restart needed for some)
                global AUTOSTART_SERVER, ENABLE_AUTO_RESTART_ON_CRASH, SERVER_JAR_NAME, JAVA_EXECUTABLE
                global JAVA_RAM, JAVA_CUSTOM_ARGS, MAX_LOG_LINES, ALLOWED_VIEW_EXTENSIONS, MAX_VIEW_FILE_SIZE_MB
                global ALLOWED_UPLOAD_EXTENSIONS, ALLOWED_EDIT_EXTENSIONS, RESTART_DELAY_SECONDS
                global AUTO_BACKUP_ENABLED, AUTO_BACKUP_INTERVAL_HOURS, BACKUP_RETENTION_COUNT

                AUTOSTART_SERVER = updated_settings.get('AUTOSTART_SERVER', DEFAULT_SETTINGS['AUTOSTART_SERVER'])
                ENABLE_AUTO_RESTART_ON_CRASH = updated_settings.get('ENABLE_AUTO_RESTART_ON_CRASH', DEFAULT_SETTINGS['ENABLE_AUTO_RESTART_ON_CRASH'])
                SERVER_JAR_NAME = updated_settings.get('SERVER_JAR_NAME', DEFAULT_SETTINGS['SERVER_JAR_NAME'])
                JAVA_EXECUTABLE = updated_settings.get('JAVA_EXECUTABLE', DEFAULT_SETTINGS['JAVA_EXECUTABLE'])
                JAVA_RAM = updated_settings.get('JAVA_RAM', DEFAULT_SETTINGS['JAVA_RAM'])
                JAVA_CUSTOM_ARGS = updated_settings.get('JAVA_CUSTOM_ARGS', DEFAULT_SETTINGS['JAVA_CUSTOM_ARGS'])
                MAX_LOG_LINES = updated_settings.get('MAX_LOG_LINES', DEFAULT_SETTINGS['MAX_LOG_LINES'])
                ALLOWED_VIEW_EXTENSIONS = set(updated_settings.get('ALLOWED_VIEW_EXTENSIONS', DEFAULT_SETTINGS['ALLOWED_VIEW_EXTENSIONS']))
                MAX_VIEW_FILE_SIZE_MB = updated_settings.get('MAX_VIEW_FILE_SIZE_MB', DEFAULT_SETTINGS['MAX_VIEW_FILE_SIZE_MB'])
                ALLOWED_UPLOAD_EXTENSIONS = set(updated_settings.get('ALLOWED_UPLOAD_EXTENSIONS', DEFAULT_SETTINGS['ALLOWED_UPLOAD_EXTENSIONS']))
                ALLOWED_EDIT_EXTENSIONS = set(updated_settings.get('ALLOWED_EDIT_EXTENSIONS', DEFAULT_SETTINGS['ALLOWED_EDIT_EXTENSIONS']))
                RESTART_DELAY_SECONDS = updated_settings.get('RESTART_DELAY_SECONDS', DEFAULT_SETTINGS['RESTART_DELAY_SECONDS'])
                AUTO_BACKUP_ENABLED = updated_settings.get('AUTO_BACKUP_ENABLED', DEFAULT_SETTINGS['AUTO_BACKUP_ENABLED'])
                AUTO_BACKUP_INTERVAL_HOURS = updated_settings.get('AUTO_BACKUP_INTERVAL_HOURS', DEFAULT_SETTINGS['AUTO_BACKUP_INTERVAL_HOURS'])
                BACKUP_RETENTION_COUNT = updated_settings.get('BACKUP_RETENTION_COUNT', DEFAULT_SETTINGS['BACKUP_RETENTION_COUNT'])

                # Update the global manager_settings dict itself
                manager_settings = updated_settings

                # Redirect to GET to show updated values/messages
                return redirect(url_for('server_settings'))
            else:
                flash("Failed to save manager settings.", "error")
                # If save failed, don't redirect, show form with previous values

    # GET request or POST failed save: Render the template
    # Pass the *current* state of manager_settings
    # Also pass DEFAULT_SETTINGS to help the template understand data types
    icon_path = Path(__file__).parent / 'static' / 'icon.png'
    return render_template('server_settings.html',
                           settings=manager_settings,
                           default_settings=DEFAULT_SETTINGS,
                           icon_exists=icon_path.exists(),
                           icon_mtime=int(icon_path.stat().st_mtime) if icon_path.exists() else 0)

@app.route('/server_properties', methods=['GET', 'POST'])
@login_required
def server_properties():
    """Route to view and edit server.properties."""
    properties_filename = "server.properties"
    # Use get_full_path for safety, even though filename is hardcoded here
    # Pass the filename directly, not a subpath string
    prop_path_obj = MINECRAFT_SERVER_PATH / properties_filename
    if not is_safe_path(prop_path_obj): # Check the constructed path
         flash("Access denied to server properties path.", "error")
         return redirect(url_for('index'))

    # Check if file exists before parsing/saving
    if not prop_path_obj.exists():
         flash(f"{properties_filename} not found in server directory.", "warning")
         # Render template with empty settings if file not found? Or redirect?
         # For now, let's render with empty/error state
         return render_template('server_properties.html', settings_list=[], filename=properties_filename)

    if request.method == 'POST':
        try:
            # Create a dictionary of the submitted settings
            submitted_settings = {}
            for key in request.form:
                submitted_settings[key] = request.form[key]

            # Use the helper function to save
            save_properties(prop_path_obj, submitted_settings)
            flash(f"{properties_filename} saved successfully.", "success")
            # Optional: Add logic here to inform the user if a server restart is needed
            flash("Server restart is required to apply the new properties.", "info")

        except (IOError, OSError, PermissionError) as e:
            flash(f"Error saving {properties_filename}: {e}", "error")
        except Exception as e:
            flash(f"An unexpected error occurred: {e}", "error")
            print(f"Unexpected error saving properties: {e}") # Log unexpected errors

        # Redirect back to the same page using GET to show updated values/messages
        return redirect(url_for('server_properties'))

    # --- GET Request Logic ---
    settings_list = parse_properties(prop_path_obj)
    if not settings_list and prop_path_obj.exists():
        # Parsing failed, but file exists - flash message already handled by parse_properties
        pass # Continue to render template, it will show empty/error

    # We need to create the 'server_properties.html' template next
    return render_template('server_properties.html',
                           settings_list=settings_list,
                           filename=properties_filename)

@app.route('/')
@login_required
def index():
    """Main page displaying server status and controls."""
    status = "Running" if is_server_running() else "Stopped"
    logs = get_latest_logs()
    return render_template('index.html', status=status, logs=logs, max_log_lines=MAX_LOG_LINES)


@app.route('/start', methods=['POST'])
@login_required
def start_server():
    """Initiates a server start in the background (non-blocking)."""
    global server_process

    if is_server_running():
        flash("Server is already running.", "warning")
        return redirect(url_for('index'))

    server_jar_path = MINECRAFT_SERVER_PATH / SERVER_JAR_NAME
    if not server_jar_path.is_file():
        flash(f"Server JAR not found at: {server_jar_path}", "error")
        return redirect(url_for('index'))

    flash("Server starting...", "info")

    def do_start():
        global server_process
        command = [JAVA_EXECUTABLE] + get_java_args() + ["-jar", str(server_jar_path), "nogui"]
        try:
            print(f"Background start: Starting server with command: {' '.join(command)}")
            print(f"Background start: Working directory: {MINECRAFT_SERVER_PATH}")
            preexec_fn = os.setsid if os.name != 'nt' else None
            server_process = subprocess.Popen(
                command,
                cwd=str(MINECRAFT_SERVER_PATH),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                encoding='utf-8',
                errors='replace',
                bufsize=1,
                preexec_fn=preexec_fn
            )
            print(f"Background start: Server process started with PID: {server_process.pid}")
            
            # Brief pause to catch immediate failures
            time.sleep(1)
            if server_process.poll() is not None:
                stderr_output = server_process.stderr.read() if server_process.stderr else ""
                print(f"Background start: Server failed immediately. Exit: {server_process.returncode}")
                print(f"Background start: Stderr: {stderr_output}")
                server_process = None
        except FileNotFoundError:
            print(f"Background start: '{JAVA_EXECUTABLE}' not found.")
            server_process = None
        except Exception as e:
            print(f"Background start: Failed to start server: {e}")
            server_process = None

    threading.Thread(target=do_start, daemon=True).start()
    return redirect(url_for('index'))


@app.route('/stop', methods=['POST'])
@login_required
def stop_server():
    """Initiates a server stop in the background (non-blocking)."""
    global server_process, user_initiated_stop

    # Quick check without blocking
    if not server_process or server_process.poll() is not None:
        flash("Server is not running.", "warning")
        server_process = None
        user_initiated_stop = True
        return redirect(url_for('index'))

    # Set the flag immediately
    user_initiated_stop = True
    print("Stop route: User initiated stop flag SET. Spawning background stop task.")
    flash("Server shutdown initiated...", "info")

    # Spawn background thread for the actual stop logic
    def do_stop():
        global server_process
        with server_management_lock:
            current_process = server_process
            if not current_process or current_process.poll() is not None:
                server_process = None
                return

            stopped_cleanly = False

            # 1. Try graceful shutdown via stdin
            try:
                print("Background stop: Sending 'stop' command via stdin...")
                if current_process.stdin and not current_process.stdin.closed:
                    current_process.stdin.write("stop\n")
                    current_process.stdin.flush()
                    try:
                        current_process.wait(timeout=20)
                        print("Background stop: Server stopped gracefully.")
                        stopped_cleanly = True
                    except subprocess.TimeoutExpired:
                        print("Background stop: Timeout waiting for graceful stop.")
                    except Exception as e:
                        print(f"Background stop: Error waiting: {e}")
                else:
                    print("Background stop: stdin unavailable.")
            except Exception as e:
                print(f"Background stop: Error sending stop: {e}")

            # 2. Force termination if necessary
            if not stopped_cleanly and current_process and current_process.poll() is None:
                try:
                    pid = current_process.pid
                    print(f"Background stop: Sending SIGTERM to {pid}...")
                    if os.name != 'nt' and hasattr(os, 'killpg'):
                        try:
                            pgid = os.getpgid(pid)
                            os.killpg(pgid, signal.SIGTERM)
                        except ProcessLookupError:
                            pass
                        except Exception:
                            current_process.terminate()
                    else:
                        current_process.terminate()

                    try:
                        current_process.wait(timeout=10)
                        print("Background stop: Terminated after SIGTERM.")
                    except subprocess.TimeoutExpired:
                        print("Background stop: SIGTERM timeout, sending SIGKILL...")
                        if os.name != 'nt' and hasattr(os, 'killpg'):
                            try:
                                pgid = os.getpgid(pid)
                                os.killpg(pgid, signal.SIGKILL)
                            except Exception:
                                current_process.kill()
                        else:
                            current_process.kill()
                        try:
                            current_process.wait(timeout=5)
                            print("Background stop: Killed.")
                        except Exception as e:
                            print(f"Background stop: Failed to kill: {e}")
                except ProcessLookupError:
                    pass
                except Exception as e:
                    print(f"Background stop: Error during force stop: {e}")

            print("Background stop: Clearing server_process handle.")
            server_process = None

    threading.Thread(target=do_stop, daemon=True).start()
    return redirect(url_for('index'))


@app.route('/restart', methods=['POST'])
@login_required
def restart_server():
    """Restart the server (stop then start) in background."""
    global server_process, user_initiated_stop

    if not is_server_running():
        flash("Server is not running. Starting instead.", "info")
        return redirect(url_for('start_server'))

    user_initiated_stop = True
    flash("Server restarting...", "info")

    def do_restart():
        global server_process, user_initiated_stop
        # Stop phase
        with server_management_lock:
            current_process = server_process
            if current_process and current_process.poll() is None:
                try:
                    if current_process.stdin and not current_process.stdin.closed:
                        current_process.stdin.write("stop\n")
                        current_process.stdin.flush()
                        current_process.wait(timeout=20)
                except:
                    try:
                        current_process.terminate()
                        current_process.wait(timeout=10)
                    except:
                        current_process.kill()
                        current_process.wait(timeout=5)
            server_process = None

        # Brief pause
        time.sleep(2)

        # Start phase
        server_jar_path = MINECRAFT_SERVER_PATH / SERVER_JAR_NAME
        if not server_jar_path.is_file():
            print("Restart: Server JAR not found")
            return

        command = [JAVA_EXECUTABLE] + get_java_args() + ["-jar", str(server_jar_path), "nogui"]
        try:
            preexec_fn = os.setsid if os.name != 'nt' else None
            server_process = subprocess.Popen(
                command, cwd=str(MINECRAFT_SERVER_PATH),
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                universal_newlines=True, encoding='utf-8', errors='replace',
                bufsize=1, preexec_fn=preexec_fn
            )
            user_initiated_stop = False
            print(f"Restart: Server started with PID {server_process.pid}")
        except Exception as e:
            print(f"Restart: Failed to start - {e}")
            server_process = None

    threading.Thread(target=do_restart, daemon=True).start()
    return redirect(url_for('index'))


@app.route('/api/system_stats')
@login_required
def system_stats():
    """API endpoint for system resource usage."""
    try:
        cpu = psutil.cpu_percent(interval=0.1)
        ram = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        return jsonify({
            'cpu': round(cpu, 1),
            'ram_percent': round(ram.percent, 1),
            'ram_used': round(ram.used / (1024**3), 2),
            'ram_total': round(ram.total / (1024**3), 2),
            'disk_percent': round(disk.percent, 1),
            'disk_used': round(disk.used / (1024**3), 2),
            'disk_total': round(disk.total / (1024**3), 2)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def monitor_server():
    """Background thread function to monitor the server process and restart if needed."""
    global server_process, user_initiated_stop

    print("Server monitor thread started.")
    while True:
        time.sleep(MONITOR_INTERVAL_SECONDS) # Check periodically

        proc_to_check = None
        is_unexpected_stop = False
        exit_code = None

        with server_management_lock:
            # Only proceed if we *think* a server process should be running
            # and it wasn't intentionally stopped by the user.
            if server_process and not user_initiated_stop:
                proc_to_check = server_process
                exit_code = proc_to_check.poll() # Check if terminated

                if exit_code is not None: # Process has terminated
                    is_unexpected_stop = True
                    print(f"Monitor: Detected unexpected server stop! Exit code: {exit_code}")
                    # Clear the global handle immediately within the lock
                    server_process = None
                    # user_initiated_stop remains False (it wasn't user triggered)

        # Perform restart logic *outside* the main lock to avoid holding it during Popen/sleep
        if is_unexpected_stop:
            print(f"Monitor: Server stopped unexpectedly (Exit Code: {exit_code}). Attempting restart in {RESTART_DELAY_SECONDS}s...")
            # Optional: Log stderr from the crashed process if possible
            if not ENABLE_AUTO_RESTART_ON_CRASH:
                print("Monitor: Detected unexpected server stop, but auto-restart is disabled.")
                # Optional: Set user_initiated_stop = True here if you want subsequent checks
                # in the same monitor cycle to ignore this stopped state.
                # user_initiated_stop = True # Or just let it be, the process is gone anyway.
                continue # Skip the restart logic and go to the next monitor cycle

            try:
                stderr_output = proc_to_check.stderr.read()
                print(f"Monitor: Stderr from stopped process:\n{stderr_output[:1000]}...") # Log first 1KB
            except Exception as e:
                print(f"Monitor: Could not read stderr from stopped process: {e}")

            time.sleep(RESTART_DELAY_SECONDS) # Wait before restarting

            print("Monitor: Initiating automatic server restart...")
            if not _start_server_process():
                print("Monitor: Automatic restart FAILED. Will retry on next cycle if server remains stopped.")
                # No need to set user_initiated_stop=True here, failure wasn't intentional stop
            else:
                print("Monitor: Automatic restart initiated successfully.")
                # _start_server_process already sets user_initiated_stop = False on success

@app.route('/command', methods=['POST'])
@login_required
def send_command():
    """Sends a command to the server via stdin."""
    command = request.form.get('command')
    referrer = request.referrer or url_for('index')

    if not command: flash("No command entered.", "warning"); return redirect(referrer)
    if not is_server_running(): flash("Cannot send command: Server not running.", "error"); return redirect(referrer)

    global server_process
    try:
        print(f"Sending command via stdin: {command}")
        if server_process and server_process.stdin and not server_process.stdin.closed:
            server_process.stdin.write(command + "\n")
            server_process.stdin.flush()
            flash(f"Command sent: /{command}", "success")
        else:
            print("Server process or stdin not available.")
            flash("Failed to send command: Server process or stdin unavailable.", "error")

    except (OSError, BrokenPipeError) as e:
        print(f"Error writing command to stdin: {e}")
        flash(f"Failed to send command: {e}", "error")
        if isinstance(e, BrokenPipeError):
             server_process = None
             flash("Server connection lost (Broken Pipe). Please check server status.", "error")

    except Exception as e:
        print(f"Unexpected error sending command: {e}")
        flash(f"Unexpected error sending command: {e}", "error")

    return redirect(referrer)


# --- File Manager Routes --- (Apply @login_required)

@app.route('/files/')
@app.route('/files/<path:subpath>')
@login_required
def files(subpath=''):
    """File browser route."""
    is_root_request = (subpath == '')
    current_dir_full_path = get_full_path(subpath) if subpath else MINECRAFT_SERVER_PATH

    if current_dir_full_path is None:
        # Use render_file_error which now redirects correctly
        return render_file_error(f"Access Denied: Invalid or unsafe path '{subpath}'.", is_root=is_root_request)

    try:
        if not current_dir_full_path.exists():
            parent_path = get_parent_rel_path(subpath)
            return render_file_error(f"Path not found: {subpath}", suggest_parent_path=parent_path, is_root=is_root_request)
        if not current_dir_full_path.is_dir():
            parent_path = get_parent_rel_path(subpath)
            return render_file_error(f"Path is not a directory: {subpath}", suggest_parent_path=parent_path, is_root=is_root_request)
    except PermissionError:
         # Redirect if permission denied checking path
         return render_file_error(f"Permission Denied checking path: {subpath}", is_root=is_root_request)
    except Exception as e:
         return render_file_error(f"Error checking path {subpath}: {e}", is_root=is_root_request)

    items = []
    listing_error = None
    try:
        for item in sorted(current_dir_full_path.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower())):
            item_rel_path = item.relative_to(MINECRAFT_SERVER_PATH)
            is_viewable = item.is_file() and item.suffix.lower() in ALLOWED_VIEW_EXTENSIONS
            is_editable = item.is_file() and item.suffix.lower() in ALLOWED_EDIT_EXTENSIONS # Check editability

            item_info = { 'name': item.name, 'path': str(item_rel_path), 'is_dir': item.is_dir(),
                          'is_file': item.is_file(), 'is_viewable': is_viewable,
                          'is_editable': is_editable, # Pass edit flag
                           'size': -1 }
            if item.is_file():
                try: item_info['size'] = item.stat().st_size
                except OSError: pass
            items.append(item_info)
    except PermissionError:
         listing_error = f"Permission denied listing directory contents: {subpath}"
    except Exception as e:
         listing_error = f"Error listing directory contents {subpath}: {e}"

    if listing_error:
        flash(listing_error, "error") # Flash error but still render template if possible

    breadcrumbs = [{'name': 'Server Root', 'path': ''}]
    current_rel_path_str = subpath
    path_parts = Path(current_rel_path_str).parts
    current_crumb_path = Path()
    for part in path_parts:
        if not part: continue
        current_crumb_path = current_crumb_path / part
        breadcrumbs.append({'name': part, 'path': str(current_crumb_path)})

    parent_path_str = get_parent_rel_path(current_rel_path_str)
    clipboard_item = session.get('clipboard')

    return render_template('file_browser.html',
                           items=items,
                           current_path=current_rel_path_str,
                           parent_path=parent_path_str,
                           breadcrumbs=breadcrumbs,
                           clipboard_item=clipboard_item,
                           config={'MAX_CONTENT_LENGTH': app.config.get('MAX_CONTENT_LENGTH'),
                                   'ALLOWED_UPLOAD_EXTENSIONS': ALLOWED_UPLOAD_EXTENSIONS}
                          )


@app.route('/view_file/<path:filepath>')
@login_required
def view_file(filepath):
    """View file content route - Modified to potentially allow editing."""
    full_path = get_full_path(filepath)
    parent_rel_path = get_parent_rel_path(filepath)
    redirect_url = url_for('files', subpath=parent_rel_path if parent_rel_path is not None else '')

    if full_path is None:
        flash(f"Access Denied: Invalid path '{filepath}'.", "error")
        return redirect(redirect_url)

    try:
        if not full_path.is_file():
            flash(f"Not a file: {filepath}", "error")
            return redirect(redirect_url)

        # Allow viewing OR editing based on separate permissions
        can_view = full_path.suffix.lower() in ALLOWED_VIEW_EXTENSIONS
        can_edit = full_path.suffix.lower() in ALLOWED_EDIT_EXTENSIONS

        if not can_view and not can_edit: # Must be at least one
             flash(f"Viewing/Editing type '{full_path.suffix}' not allowed.", "warning")
             return redirect(redirect_url)

        file_size = full_path.stat().st_size
        # Apply size limit for viewing/editing
        if file_size > MAX_VIEW_FILE_SIZE_MB * 1024 * 1024:
            flash(f"File too large to view/edit (>{MAX_VIEW_FILE_SIZE_MB}MB).", "warning")
            return redirect(redirect_url)

        content = None
        try:
             content = full_path.read_text(encoding='utf-8')
        except UnicodeDecodeError:
             # Fallback encoding if UTF-8 fails
             content = full_path.read_text(encoding='latin-1', errors='replace')
        except Exception as read_err:
             raise IOError(f"Could not read file content: {read_err}") # Re-raise as IOError

        if content is None: # Should not happen if read_text succeeds or raises
             flash(f"Failed to read content for {filepath}", "error")
             return redirect(redirect_url)

        mimetype = mimetypes.guess_type(full_path)[0] or 'text/plain'
        # Use the same template for viewing and editing, control via 'can_edit' flag
        template_name = 'file_viewer.html'
        
        # Check for popup mode (fullscreen editor in new window)
        popup_mode = request.args.get('popup', '0') == '1'

        return render_template(template_name,
                               filename=full_path.name,
                               filepath=filepath, # Pass relative path
                               content=content,
                               mimetype=mimetype,
                               can_edit=can_edit, # Pass edit flag to template
                               popup_mode=popup_mode # Pass popup mode flag
                               )

    except PermissionError: flash(f"Permission denied to read file: {filepath}", "error")
    except (OSError, IOError) as e: flash(f"Error accessing file {filepath}: {e}", "error")
    except Exception as e: flash(f"Unexpected error viewing file {filepath}: {e}", "error")

    # Fallback redirect on error
    return redirect(redirect_url)

@app.route('/create_folder', methods=['POST'])
@login_required
def create_folder():
    """Creates a new folder."""
    target_rel_dir = request.form.get('target_dir', '')
    new_folder_name = request.form.get('new_name', '').strip()
    redirect_target = url_for('files', subpath=target_rel_dir)

    if not new_folder_name:
        flash("No folder name provided.", "error")
        return redirect(redirect_target)

    # Basic validation for folder name (similar to rename)
    if '/' in new_folder_name or '\\' in new_folder_name or new_folder_name == '.' or new_folder_name == '..':
        flash("Invalid characters or name for folder.", "error")
        return redirect(redirect_target)

    target_full_dir = get_full_path(target_rel_dir) if target_rel_dir else MINECRAFT_SERVER_PATH
    if target_full_dir is None or not target_full_dir.is_dir():
        flash(f"Invalid base directory '{target_rel_dir}'.", "error")
        return redirect(url_for('files')) # Redirect to root on base dir error

    new_folder_path = target_full_dir / new_folder_name

    # Safety check on the final path
    if not is_safe_path(new_folder_path, base_path=MINECRAFT_SERVER_PATH):
         flash("Cannot create folder at unsafe path.", "error")
         return redirect(redirect_target)
    if new_folder_path.exists():
        flash(f"Folder or file '{new_folder_name}' already exists.", "error")
        return redirect(redirect_target)

    try:
        os.makedirs(new_folder_path) # Use os.makedirs for simplicity, handles intermediate dirs if needed by mistake
        # Alternatively: new_folder_path.mkdir() # Use pathlib if preferred
        flash(f"Folder '{new_folder_name}' created successfully.", "success")
    except PermissionError:
        flash(f"Permission denied to create folder in '{target_rel_dir}'.", "error")
    except OSError as e:
        flash(f"Error creating folder '{new_folder_name}': {e}", "error")
    except Exception as e:
        print(f"Unexpected error creating folder: {e}")
        flash(f"An unexpected error occurred: {e}", "error")

    return redirect(redirect_target)


@app.route('/create_file', methods=['POST'])
@login_required
def create_file():
    """Creates a new empty file."""
    target_rel_dir = request.form.get('target_dir', '')
    new_file_name = request.form.get('new_name', '').strip()
    redirect_target = url_for('files', subpath=target_rel_dir)

    if not new_file_name:
        flash("No file name provided.", "error")
        return redirect(redirect_target)

    # Basic validation for file name (similar to rename)
    if '/' in new_file_name or '\\' in new_file_name or not new_file_name:
        flash("Invalid characters or empty file name.", "error")
        return redirect(redirect_target)

    # Suggest adding common extensions if none provided (optional enhancement)
    # if '.' not in new_file_name:
    #     flash("Consider adding a file extension like .txt or .yml", "info") # Example

    target_full_dir = get_full_path(target_rel_dir) if target_rel_dir else MINECRAFT_SERVER_PATH
    if target_full_dir is None or not target_full_dir.is_dir():
        flash(f"Invalid base directory '{target_rel_dir}'.", "error")
        return redirect(url_for('files')) # Redirect to root on base dir error

    new_file_path = target_full_dir / new_file_name

    # Safety check on the final path
    if not is_safe_path(new_file_path, base_path=MINECRAFT_SERVER_PATH):
        flash("Cannot create file at unsafe path.", "error")
        return redirect(redirect_target)
    if new_file_path.exists():
        flash(f"File or folder '{new_file_name}' already exists.", "error")
        return redirect(redirect_target)

    try:
        # Create an empty file using pathlib's touch
        new_file_path.touch()
        # Alternatively using open:
        # with open(new_file_path, 'w') as f:
        #     pass
        flash(f"File '{new_file_name}' created successfully.", "success")
    except PermissionError:
        flash(f"Permission denied to create file in '{target_rel_dir}'.", "error")
    except OSError as e:
        flash(f"Error creating file '{new_file_name}': {e}", "error")
    except Exception as e:
        print(f"Unexpected error creating file: {e}")
        flash(f"An unexpected error occurred: {e}", "error")

    return redirect(redirect_target)

# --- Make sure existing routes like files, delete, rename etc. are also secured ---
# Ensure @login_required decorator is present above all sensitive routes.

@app.route('/download/<path:filepath>')
@login_required
def download_file(filepath):
    """Download a file."""
    full_path = get_full_path(filepath)
    parent_rel_path = get_parent_rel_path(filepath)
    redirect_url = url_for('files', subpath=parent_rel_path if parent_rel_path is not None else '')

    if full_path is None or not full_path.is_file():
        flash("Download Error: File not found or access denied.", "error")
        return redirect(redirect_url)

    try:
        directory = str(full_path.parent)
        filename = full_path.name
        return send_from_directory(directory, filename, as_attachment=True)
    except FileNotFoundError: abort(404, description="File not found.")
    except PermissionError: flash(f"Permission denied to download '{filename}'.", "error")
    except Exception as e: print(f"Error during download for {filepath}: {e}"); flash(f"Error downloading file: {e}", "error")

    return redirect(redirect_url)


@app.route('/delete', methods=['POST'])
@login_required
def delete_item():
    """Delete a file or directory."""
    relative_path = request.form.get('path')
    referrer = request.referrer or url_for('files') # Go back where user was
    parent_rel_path = get_parent_rel_path(relative_path)
    redirect_target = url_for('files', subpath=parent_rel_path if parent_rel_path is not None else '')

    if not relative_path: flash("No path specified for deletion.", "error"); return redirect(referrer)

    full_path = get_full_path(relative_path)
    if full_path is None: flash(f"Invalid path for deletion: {relative_path}", "error"); return redirect(redirect_target)
    if not full_path.exists(): flash(f"Item not found: {relative_path}", "error"); return redirect(redirect_target)
    if full_path == MINECRAFT_SERVER_PATH: flash("CRITICAL: Cannot delete the root server directory.", "error"); return redirect(url_for('files', subpath=''))

    try:
        item_name = full_path.name
        if full_path.is_file(): os.remove(full_path); flash(f"File '{item_name}' deleted.", "success")
        elif full_path.is_dir(): shutil.rmtree(full_path); flash(f"Directory '{item_name}' and contents deleted.", "success")
        else: flash(f"'{item_name}' not a file or directory.", "warning")
        return redirect(redirect_target) # Redirect to parent dir after successful delete
    except PermissionError: flash(f"Permission denied to delete '{full_path.name}'.", "error")
    except OSError as e: flash(f"Error deleting '{full_path.name}': {e}", "error")
    except Exception as e: print(f"Unexpected delete error: {e}"); flash(f"Unexpected error deleting: {e}", "error")

    return redirect(referrer) # Redirect back to original page on error


@app.route('/rename', methods=['POST'])
@login_required
def rename_item():
    """Rename a file or directory."""
    original_rel_path = request.form.get('original_path')
    new_name = request.form.get('new_name', '').strip()
    parent_rel_path = get_parent_rel_path(original_rel_path)
    redirect_target = url_for('files', subpath=parent_rel_path if parent_rel_path is not None else '')

    if not original_rel_path or not new_name: flash("Original path or new name missing.", "error"); return redirect(redirect_target)
    # Basic validation for new name
    if '/' in new_name or '\\' in new_name or new_name == '..' or not new_name: flash("Invalid characters or empty new name.", "error"); return redirect(redirect_target)

    original_full_path = get_full_path(original_rel_path)
    if original_full_path is None or not original_full_path.exists(): flash(f"Item not found or invalid: {original_rel_path}", "error"); return redirect(redirect_target)
    if original_full_path == MINECRAFT_SERVER_PATH: flash("Cannot rename the root server directory.", "error"); return redirect(url_for('files', subpath=''))

    new_full_path = original_full_path.parent / new_name
    
    # Check if name hasn't changed
    if original_full_path == new_full_path:
        flash("No changes were made.", "info")
        return redirect(redirect_target)

    # Extra safety check on the *new* path
    if not is_safe_path(new_full_path): flash("Renaming would create an unsafe path.", "error"); return redirect(redirect_target)
    if new_full_path.exists(): flash(f"'{new_name}' already exists.", "error"); return redirect(redirect_target)

    try:
        os.rename(original_full_path, new_full_path)
        flash(f"Renamed '{original_full_path.name}' to '{new_name}'.", "success")
    except PermissionError: flash(f"Permission denied to rename.", "error")
    except OSError as e: flash(f"Error renaming: {e}", "error")
    except Exception as e: print(f"Rename error: {e}"); flash(f"Unexpected error renaming: {e}", "error")

    return redirect(redirect_target) # Redirect to parent directory


@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    """Upload files and folders to the specified directory."""
    target_rel_dir = request.form.get('target_dir', '')
    redirect_target = url_for('files', subpath=target_rel_dir)

    target_full_dir = get_full_path(target_rel_dir) if target_rel_dir else MINECRAFT_SERVER_PATH
    if target_full_dir is None or not target_full_dir.is_dir():
        flash(f"Invalid upload directory '{target_rel_dir}'.", "error"); return redirect(url_for('files'))

    # Collect files and paths
    uploaded_files = request.files.getlist('files[]')
    relative_paths = request.form.getlist('paths[]') # Parallel array to files[]

    # Fallback for single file upload (standard input type="file")
    if not uploaded_files and 'file' in request.files:
        val = request.files['file']
        if val and val.filename:
            uploaded_files = [val]
            relative_paths = ['']

    if not uploaded_files:
        flash('No files selected.', "warning"); return redirect(redirect_target)

    success_count = 0
    error_count = 0
    
    for i, file in enumerate(uploaded_files):
        if not file or file.filename == '': continue
        
        filename = secure_filename(file.filename)
        if not allowed_file(filename):
            error_count += 1
            continue

        # Determine destination directory
        final_dest_dir = target_full_dir
        rel_path = relative_paths[i] if i < len(relative_paths) else ''
        
        if rel_path and rel_path.strip() != '.':
            # Secure the relative path components
            parts = [secure_filename(p) for p in rel_path.split('/') if p and p != '..' and p != '.']
            if parts:
                try:
                    final_dest_dir = target_full_dir.joinpath(*parts)
                    # Check jail
                    if not is_safe_path(final_dest_dir):
                        error_count += 1; continue
                    final_dest_dir.mkdir(parents=True, exist_ok=True)
                except Exception as e:
                    print(f"Error creating dir {rel_path}: {e}")
                    error_count += 1; continue

        dest_path = final_dest_dir / filename
        
        if not is_safe_path(dest_path):
            error_count += 1; continue
            
        if dest_path.exists(): 
             # Skip or overwrite? Standard behavior is usually overwrite or error.
             # Given bulk upload, maybe overwrite or skip silently?
             # Let's overwrite for now or skip. User didn't specify. 
             # Flash handles "already exists" for single file. 
             # For bulk, blocking on one file is bad.
             pass 

        try:
            file.save(dest_path)
            success_count += 1
        except Exception as e:
            print(f"Error saving {filename}: {e}")
            error_count += 1

    if success_count > 0:
        msg = f"Uploaded {success_count} files."
        if error_count > 0: msg += f" ({error_count} failed/skipped)"
        flash(msg, "success" if error_count == 0 else "warning")
    elif error_count > 0:
        flash(f"Failed to upload {error_count} files.", "error")
    else:
        flash("No valid files processed.", "warning")

    return redirect(redirect_target)


# --- Copy/Paste/Move using Session --- (Apply @login_required)

@app.route('/clipboard/copy', methods=['POST'])
@login_required
def clipboard_copy():
    """Copies item path to session clipboard."""
    relative_path = request.form.get('path')
    referrer = request.referrer or url_for('files')
    if not relative_path: flash("No path specified.", "error"); return redirect(referrer)

    full_path = get_full_path(relative_path)
    if full_path is None or not full_path.exists(): flash(f"Cannot copy: '{relative_path}' not found/invalid.", "error"); return redirect(referrer)

    session['clipboard'] = {'action': 'copy', 'path': relative_path}
    flash(f"Copied '{Path(relative_path).name}' to clipboard.", "info")
    return redirect(referrer)

@app.route('/clipboard/cut', methods=['POST'])
@login_required
def clipboard_cut():
    """Marks item path for moving (cut) in session clipboard."""
    relative_path = request.form.get('path')
    referrer = request.referrer or url_for('files')
    if not relative_path: flash("No path specified.", "error"); return redirect(referrer)

    full_path = get_full_path(relative_path)
    if full_path is None or not full_path.exists(): flash(f"Cannot cut: '{relative_path}' not found/invalid.", "error"); return redirect(referrer)
    if full_path == MINECRAFT_SERVER_PATH: flash("Cannot cut the root server directory.", "error"); return redirect(url_for('files', subpath=''))

    session['clipboard'] = {'action': 'cut', 'path': relative_path}
    flash(f"Marked '{Path(relative_path).name}' to move (cut).", "info")
    return redirect(referrer)

@app.route('/clipboard/clear', methods=['POST', 'GET']) # Allow GET for simple link clearing
@login_required
def clipboard_clear():
    """Clears the clipboard."""
    referrer = request.referrer or url_for('files')
    if 'clipboard' in session: session.pop('clipboard', None); flash("Clipboard cleared.", "info")
    else: flash("Clipboard was already empty.", "info")
    return redirect(referrer)


@app.route('/clipboard/paste', methods=['POST'])
@login_required
def clipboard_paste():
    """Pastes item from clipboard to target directory."""
    target_rel_dir = request.form.get('target_dir', '')
    redirect_target = url_for('files', subpath=target_rel_dir)

    clipboard = session.get('clipboard')
    if not clipboard: flash("Clipboard empty.", "warning"); return redirect(redirect_target)

    source_rel_path = clipboard['path']
    action = clipboard['action']

    source_full_path = get_full_path(source_rel_path)
    if source_full_path is None or not source_full_path.exists():
        flash(f"Source '{source_rel_path}' not found/invalid. Clipboard cleared.", "error")
        session.pop('clipboard', None); return redirect(redirect_target)

    target_full_dir = get_full_path(target_rel_dir) if target_rel_dir else MINECRAFT_SERVER_PATH
    if target_full_dir is None or not target_full_dir.is_dir(): flash(f"Invalid paste destination '{target_rel_dir}'.", "error"); return redirect(redirect_target)

    destination_path = target_full_dir / source_full_path.name

    # Prevent pasting onto self or into self (for dirs)
    if source_full_path == destination_path:
         if action == 'copy': flash("Source and destination are the same.", "info"); return redirect(redirect_target)
         else: flash("Cannot cut/move item onto itself.", "warning"); return redirect(redirect_target)
    # Use Path.is_relative_to if available (Python 3.9+) for clarity
    try:
      if source_full_path.is_dir() and destination_path.resolve().is_relative_to(source_full_path.resolve()):
          flash("Cannot paste a directory inside itself or one of its subdirectories.", "error"); return redirect(redirect_target)
    except AttributeError: # Fallback for older Python if is_relative_to doesn't exist
         # Less robust check, might miss some edge cases like symlinks
         if str(destination_path.resolve()).startswith(str(source_full_path.resolve()) + os.sep):
              flash("Cannot paste a directory inside itself or one of its subdirectories.", "error"); return redirect(redirect_target)

    if destination_path.exists(): flash(f"'{destination_path.name}' already exists in destination. Paste cancelled.", "error"); return redirect(redirect_target)
    # Final safety check
    if not is_safe_path(destination_path): flash("Paste operation results in an unsafe path.", "error"); return redirect(redirect_target)

    try:
        if action == 'copy':
            if source_full_path.is_file(): shutil.copy2(source_full_path, destination_path) # Preserves metadata
            elif source_full_path.is_dir(): shutil.copytree(source_full_path, destination_path, symlinks=True, dirs_exist_ok=False)
            flash(f"Copied '{source_full_path.name}'.", "success")
        elif action == 'cut':
            shutil.move(str(source_full_path), str(destination_path))
            flash(f"Moved '{source_full_path.name}'.", "success")
            session.pop('clipboard', None) # Clear clipboard after successful cut/move
    except PermissionError as e: flash(f"Permission denied during {action}: {e}", "error")
    except (shutil.Error, OSError) as e: flash(f"Error during {action}: {e}", "error")
    except Exception as e: print(f"Paste error: {e}"); flash(f"Unexpected error during {action}: {e}", "error")

    return redirect(redirect_target)


@app.route('/api/move', methods=['POST'])
@login_required
def api_move_item():
    """API endpoint to move a file or directory. Returns JSON."""
    data = request.get_json()
    if not data:
        return jsonify(success=False, message="No JSON data provided"), 400
    
    source_rel_path = data.get('source_path')
    target_rel_dir = data.get('target_dir', '')
    
    if not source_rel_path:
        return jsonify(success=False, message="No source path specified"), 400
    
    # Validate source
    source_full_path = get_full_path(source_rel_path)
    if source_full_path is None or not source_full_path.exists():
        return jsonify(success=False, message=f"Source not found: {source_rel_path}"), 404
    
    if source_full_path == MINECRAFT_SERVER_PATH:
        return jsonify(success=False, message="Cannot move the root server directory"), 403
    
    # Validate target directory
    target_full_dir = get_full_path(target_rel_dir) if target_rel_dir else MINECRAFT_SERVER_PATH
    if target_full_dir is None or not target_full_dir.is_dir():
        return jsonify(success=False, message=f"Invalid target directory: {target_rel_dir}"), 400
    
    destination_path = target_full_dir / source_full_path.name
    
    # Prevent moving onto self
    if source_full_path == destination_path:
        return jsonify(success=False, message="Source and destination are the same"), 400
    
    # Prevent moving directory into itself
    try:
        if source_full_path.is_dir() and destination_path.resolve().is_relative_to(source_full_path.resolve()):
            return jsonify(success=False, message="Cannot move a directory inside itself"), 400
    except AttributeError:
        if str(destination_path.resolve()).startswith(str(source_full_path.resolve()) + os.sep):
            return jsonify(success=False, message="Cannot move a directory inside itself"), 400
    
    # Check if destination already exists
    if destination_path.exists():
        return jsonify(success=False, message=f"'{destination_path.name}' already exists in destination"), 409
    
    # Final safety check
    if not is_safe_path(destination_path):
        return jsonify(success=False, message="Move would create an unsafe path"), 403
    
    try:
        shutil.move(str(source_full_path), str(destination_path))
        return jsonify(
            success=True, 
            message=f"Moved '{source_full_path.name}' to '{target_rel_dir or 'Server Root'}'"
        )
    except PermissionError as e:
        return jsonify(success=False, message=f"Permission denied: {e}"), 403
    except (shutil.Error, OSError) as e:
        return jsonify(success=False, message=f"Move failed: {e}"), 500
    except Exception as e:
        print(f"API Move error: {e}")
        return jsonify(success=False, message=f"Unexpected error: {e}"), 500

@app.route('/save_file', methods=['POST'])
@login_required
def save_file():
    """Saves the edited content back to the file."""
    relative_path = request.form.get('filepath')
    new_content = request.form.get('content')
    # Redirect back to the editor page after saving
    redirect_target = url_for('view_file', filepath=relative_path) if relative_path else url_for('files')

    if relative_path is None or new_content is None:
        flash("Error: Missing file path or content.", "error")
        # Go back to wherever the form was submitted from
        return redirect(request.referrer or url_for('files'))

    full_path = get_full_path(relative_path)
    parent_rel_path = get_parent_rel_path(relative_path)

    if full_path is None:
        flash(f"Save Error: Invalid or unsafe path '{relative_path}'.", "error")
        # Redirect to parent dir if path is invalid
        return redirect(url_for('files', subpath=parent_rel_path if parent_rel_path is not None else ''))

    try:
        if not full_path.is_file():
             flash(f"Save Error: Target path '{relative_path}' is not a file or doesn't exist.", "error")
             # Redirect to parent if not a file
             return redirect(url_for('files', subpath=parent_rel_path if parent_rel_path is not None else ''))
        if full_path.suffix.lower() not in ALLOWED_EDIT_EXTENSIONS:
             flash(f"Save Error: Editing files with extension '{full_path.suffix}' is not allowed.", "error")
             # Redirect back to editor if extension not allowed (shouldn't happen if view_file logic is correct)
             return redirect(redirect_target)

        print(f"Attempting to save changes to: {full_path}")
        # Normalize line endings to Unix-style (\n) before writing, common for text configs
        # Or handle based on file type if needed
        normalized_content = new_content.replace('\r\n', '\n')
        full_path.write_text(normalized_content, encoding='utf-8', errors='replace')
        flash(f"File '{full_path.name}' saved successfully.", "success")
    except PermissionError: flash(f"Save Error: Permission denied to write to '{full_path.name}'.", "error")
    except OSError as e: flash(f"Save Error: Could not write file '{full_path.name}': {e}", "error")
    except Exception as e:
        print(f"Unexpected error saving file {relative_path}: {e}")
        flash(f"Save Error: An unexpected error occurred: {e}", "error")

    # Redirect back to the editor page regardless of success/failure to see messages
    return redirect(redirect_target)


@app.route('/api/save_file', methods=['POST'])
@login_required
def api_save_file():
    """API endpoint for AJAX file saving. Returns JSON instead of redirect."""
    data = request.get_json()
    if not data:
        return jsonify(success=False, message="No JSON data provided"), 400
    
    relative_path = data.get('filepath')
    new_content = data.get('content')
    
    if relative_path is None or new_content is None:
        return jsonify(success=False, message="Missing file path or content"), 400
    
    full_path = get_full_path(relative_path)
    
    if full_path is None:
        return jsonify(success=False, message=f"Invalid or unsafe path: {relative_path}"), 403
    
    try:
        if not full_path.is_file():
            return jsonify(success=False, message=f"Target path is not a file: {relative_path}"), 404
        
        if full_path.suffix.lower() not in ALLOWED_EDIT_EXTENSIONS:
            return jsonify(success=False, message=f"Editing '{full_path.suffix}' files not allowed"), 403
        
        # Normalize line endings
        normalized_content = new_content.replace('\r\n', '\n')
        full_path.write_text(normalized_content, encoding='utf-8', errors='replace')
        
        return jsonify(success=True, message=f"File '{full_path.name}' saved successfully")
    except PermissionError:
        return jsonify(success=False, message=f"Permission denied: {full_path.name}"), 403
    except OSError as e:
        return jsonify(success=False, message=f"Could not write file: {e}"), 500
    except Exception as e:
        print(f"API Save error: {e}")
        return jsonify(success=False, message=f"Unexpected error: {e}"), 500


@app.route('/api/download_icon', methods=['POST'])
@login_required
def api_download_icon():
    """Download an icon from URL and save as static/icon.png."""
    import urllib.request
    import urllib.error
    
    data = request.get_json()
    if not data:
        return jsonify(success=False, message="No JSON data provided"), 400
    
    url = data.get('url', '').strip()
    if not url:
        return jsonify(success=False, message="No URL provided"), 400
    
    # Validate URL format
    if not url.startswith(('http://', 'https://')):
        return jsonify(success=False, message="Invalid URL - must start with http:// or https://"), 400
    
    try:
        # Download the image
        icon_path = Path(__file__).parent / 'static' / 'icon.png'
        
        # Create static folder if it doesn't exist
        icon_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Download with timeout
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=10) as response:
            content_type = response.headers.get('Content-Type', '')
            if 'image' not in content_type.lower():
                return jsonify(success=False, message=f"URL does not point to an image (got {content_type})"), 400
            
            image_data = response.read()
            
            # Save the icon
            with open(icon_path, 'wb') as f:
                f.write(image_data)
        
        return jsonify(success=True, message=f"Icon downloaded and saved ({len(image_data)} bytes)")
    
    except urllib.error.URLError as e:
        return jsonify(success=False, message=f"Failed to download: {e.reason}"), 400
    except urllib.error.HTTPError as e:
        return jsonify(success=False, message=f"HTTP error {e.code}: {e.reason}"), 400
    except Exception as e:
        return jsonify(success=False, message=f"Error: {str(e)}"), 500



@app.route('/api/regenerate_secret_key', methods=['POST'])
@login_required
def regenerate_secret_key():
    """Regenerates the Flask secret key and saves it."""
    new_key = os.urandom(24)
    try:
        with open(SECRET_KEY_FILE, 'wb') as f:
            f.write(new_key)
        app.secret_key = new_key
        return jsonify({'status': 'success', 'message': 'Secret key regenerated. Since session validation depends on the key, you will be logged out.'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': f"Failed to save secret key: {e}"}), 500

# --- API Routes --- (Apply @login_required)

@app.route('/status_api')
@login_required
def status_api():
    """API endpoint to get server status."""
    return jsonify(status="Running" if is_server_running() else "Stopped")

@app.route('/backup_now', methods=['POST'])
@login_required
def backup_now():
    """Manually trigger a backup (non-blocking)."""
    def do_backup():
        success, result = create_backup()
        if success:
            print(f"Background backup completed: {result}")
        else:
            print(f"Background backup failed: {result}")
    
    threading.Thread(target=do_backup, daemon=True).start()
    return jsonify(success=True, message="Backup started in background...")

@app.route('/logs_api')
@login_required
def logs_api():
    """API endpoint to get latest logs."""
    return jsonify(logs=get_latest_logs())


# --- Cleanup on Exit ---
import atexit

def cleanup_server_process():
    """Ensures server process is terminated when Flask app exits."""
    global server_process
    if is_server_running():
        print("Flask app exiting, attempting graceful shutdown of Minecraft server...")
        try:
            if server_process.stdin and not server_process.stdin.closed:
                 server_process.stdin.write("stop\n")
                 server_process.stdin.flush()
                 server_process.wait(timeout=15)
                 print("Server stopped via stdin on app exit.")
            else: raise Exception("Stdin closed or unavailable")
        except Exception as e:
            print(f"Stdin stop failed on exit ({e}), forcing termination...")
            try:
                if os.name != 'nt' and hasattr(os, 'killpg') and hasattr(os, 'getpgid'):
                    try: os.killpg(os.getpgid(server_process.pid), signal.SIGKILL)
                    except: server_process.kill()
                else: server_process.kill()
                server_process.wait(timeout=5)
                print("Server process forcefully terminated on app exit.")
            except Exception as kill_e:
                 print(f"Error during forceful termination on exit: {kill_e}")
        server_process = None

atexit.register(cleanup_server_process)


# --- Run the App ---
if __name__ == '__main__':
    # Reload settings one last time before starting server/monitor
    # in case the JSON file was modified externally since app init
    load_settings()
    # Apply settings again (redundant if load_settings didn't change anything, but safe)
    app.config['ALLOW_REGISTRATION'] = manager_settings.get('ALLOW_REGISTRATION', DEFAULT_SETTINGS['ALLOW_REGISTRATION'])
    try:
        max_upload_mb = int(manager_settings.get('MAX_UPLOAD_SIZE_MB', DEFAULT_SETTINGS['MAX_UPLOAD_SIZE_MB']))
        app.config['MAX_CONTENT_LENGTH'] = max_upload_mb * 1024 * 1024
    except ValueError:
        app.config['MAX_CONTENT_LENGTH'] = DEFAULT_SETTINGS['MAX_UPLOAD_SIZE_MB'] * 1024 * 1024
    AUTOSTART_SERVER = manager_settings.get('AUTOSTART_SERVER', DEFAULT_SETTINGS['AUTOSTART_SERVER'])
    ENABLE_AUTO_RESTART_ON_CRASH = manager_settings.get('ENABLE_AUTO_RESTART_ON_CRASH', DEFAULT_SETTINGS['ENABLE_AUTO_RESTART_ON_CRASH'])
    print("-------------------------------------------------------")
    print("---            Minecraft Server Manager             ---")
    print(f"Server Directory: {MINECRAFT_SERVER_PATH}")
    print(f"Settings File: {SETTINGS_FILE}") # Add this
    print(f"Database File: {DATABASE}")
    print(f"MC Auto-Start: {'ENABLED' if AUTOSTART_SERVER else 'DISABLED'}")
    print(f"MC Auto-Restart: {'ENABLED' if ENABLE_AUTO_RESTART_ON_CRASH else 'DISABLED'}")
    print(f"Allow Register: {'ENABLED' if app.config['ALLOW_REGISTRATION'] else 'DISABLED'}") # Use Flask config
    print("-------------------------------------------------------")

    # --- Autostart Logic --- <<< MODIFY/ADD THIS SECTION
    if AUTOSTART_SERVER:
        pass
#        print("Configuration: Autostart is ENABLED.")
        try_start_server_on_launch()
    else:
        pass
#        print("Configuration: Autostart is DISABLED.")
    # ----------------------

    # --- Start the Background Monitoring Thread ---
    print("Starting server monitoring thread...")
    monitor_thread = threading.Thread(target=monitor_server, daemon=True)
    monitor_thread.start()
    print("Monitoring thread active.")
    # ---------------------------------------------

    # --- Socket.IO Log Streaming Background Task ---
    def log_stream_task():
        """Background task for streaming log updates via Socket.IO."""
        global last_log_position, last_log_content
        while True:
            try:
                if LOG_FILE.is_file():
                    current_size = LOG_FILE.stat().st_size
                    if current_size < last_log_position:
                        # Log file was rotated/truncated, reset
                        last_log_position = 0
                    
                    if current_size > last_log_position:
                        with open(LOG_FILE, 'r', encoding='utf-8', errors='ignore') as f:
                            f.seek(last_log_position)
                            new_content = f.read()
                            last_log_position = f.tell()
                            if new_content.strip():
                                socketio.emit('log_update', {'data': new_content})
            except Exception as e:
                print(f"Log stream error: {e}")
            socketio.sleep(0.5)  # Check every 500ms
    
    socketio.start_background_task(log_stream_task)
    print("Log streaming task started.")
    # -----------------------------------------------

    # --- Start Backup Scheduler Thread ---
    backup_thread = threading.Thread(target=backup_scheduler, daemon=True)
    backup_thread.start()
    print("Backup scheduler thread started.")
    # -------------------------------------

    socketio.run(app, debug=False, host='0.0.0.0', port=8080)
