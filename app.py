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
from functools import wraps
from pathlib import Path
from flask import (
    Flask, render_template, request, redirect, url_for,
    jsonify, flash, abort, Response, send_from_directory, session, g # Added g
)
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash # Added for passwords

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

SETTINGS_FILE = MINECRAFT_SERVER_PATH / 'manager_settings.json'

DEFAULT_SETTINGS = {
    "AUTOSTART_SERVER": False,
    "ENABLE_AUTO_RESTART_ON_CRASH": False,
    "ALLOW_REGISTRATION": True,
    "SERVER_JAR_NAME": "server.jar",
    "JAVA_EXECUTABLE": "java",
    "JAVA_ARGS": ["-Xmx2G", "-Xms1G"],
    "LOG_FILE_DISPLAY": str(MINECRAFT_SERVER_PATH / "logs" / "latest.log"), # For display only
    "DATABASE_DISPLAY": str(MINECRAFT_SERVER_PATH / 'users.db'), # For display only
    "MAX_LOG_LINES": 50,
    "ALLOWED_VIEW_EXTENSIONS": ['.txt', '.log', '.yml', '.yaml', '.json', '.properties', '.md'],
    "MAX_VIEW_FILE_SIZE_MB": 5,
    "ALLOWED_UPLOAD_EXTENSIONS": ['jar', 'zip', 'dat', 'json', 'yml', 'yaml', 'txt', 'conf', 'properties', 'schem', 'schematic', 'mcstructure', 'mcfunction', 'mcmeta', 'png', 'jpg', 'jpeg', 'gif'],
    "MAX_UPLOAD_SIZE_MB": 4096,
    "ALLOWED_EDIT_EXTENSIONS": ['.txt', '.yml', '.yaml', '.json', '.properties', '.conf', '.cfg'],
    "START_MODE": "jar",
    "SERVER_SCRIPT_NAME": "start.sh",
    "RESTART_DELAY_SECONDS": 5
}

DATABASE = MINECRAFT_SERVER_PATH / 'users.db' # Added database path
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
app = Flask(__name__)
app.secret_key = os.urandom(24)

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
JAVA_ARGS = manager_settings.get('JAVA_ARGS', DEFAULT_SETTINGS['JAVA_ARGS'])
START_MODE = manager_settings.get('START_MODE', DEFAULT_SETTINGS['START_MODE'])
SERVER_SCRIPT_NAME = manager_settings.get('SERVER_SCRIPT_NAME', DEFAULT_SETTINGS['SERVER_SCRIPT_NAME'])
MAX_LOG_LINES = manager_settings.get('MAX_LOG_LINES', DEFAULT_SETTINGS['MAX_LOG_LINES'])
ALLOWED_VIEW_EXTENSIONS = set(manager_settings.get('ALLOWED_VIEW_EXTENSIONS', DEFAULT_SETTINGS['ALLOWED_VIEW_EXTENSIONS']))
MAX_VIEW_FILE_SIZE_MB = manager_settings.get('MAX_VIEW_FILE_SIZE_MB', DEFAULT_SETTINGS['MAX_VIEW_FILE_SIZE_MB'])
ALLOWED_UPLOAD_EXTENSIONS = set(manager_settings.get('ALLOWED_UPLOAD_EXTENSIONS', DEFAULT_SETTINGS['ALLOWED_UPLOAD_EXTENSIONS']))
ALLOWED_EDIT_EXTENSIONS = set(manager_settings.get('ALLOWED_EDIT_EXTENSIONS', DEFAULT_SETTINGS['ALLOWED_EDIT_EXTENSIONS']))
RESTART_DELAY_SECONDS = manager_settings.get('RESTART_DELAY_SECONDS', DEFAULT_SETTINGS['RESTART_DELAY_SECONDS'])
LOG_FILE = MINECRAFT_SERVER_PATH / "logs" / "latest.log"
DATABASE = MINECRAFT_SERVER_PATH / 'users.db'

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

# --- Function for Server Autostart ---
def try_start_server_on_launch():
    """
    Attempts to start the Minecraft server on launch if AUTOSTART_SERVER is true,
    respecting the START_MODE setting by calling _start_server_process.
    """
    # Ensure globals holding settings are accessible
    # Note: These globals should be loaded from manager_settings *before* this function is called
    global server_process, AUTOSTART_SERVER, START_MODE

    # 1. Check if autostart is enabled in settings
    if not AUTOSTART_SERVER:
        print("Autostart Skipped: AUTOSTART_SERVER setting is disabled.")
        return # Exit if autostart is not enabled

    # 2. Check if the server process seems to be running already
    # Use the thread-safe helper function
    if is_server_running():
        print("Autostart Skipped: Server process appears to be running already.")
        return # Exit if server is already running

    # 3. Log the attempt and the mode being used
    print(f"Autostart: Attempting server launch using mode: {START_MODE}")

    # 4. Call the internal start function which handles mode logic
    # _start_server_process returns True on success attempt, False on failure
    if not _start_server_process():
        # Error details are printed within _start_server_process
        print("Autostart Error: Server failed to start automatically. Check previous logs.")
        # No flash message needed here as this runs before the first request
    else:
        # Success message printed within _start_server_process
        print("Autostart: Server launch sequence initiated successfully.")
        # _start_server_process handles setting the global server_process variable on success

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
    """Inject user variable into templates"""
    return dict(user=g.user)

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
    Internal function to launch the Minecraft server subprocess based on START_MODE.
    Assumes lock is NOT held by caller. Manages globals directly.
    Returns True on successful launch attempt, False otherwise.
    """
    global server_process, user_initiated_stop, START_MODE, SERVER_JAR_NAME, SERVER_SCRIPT_NAME # Add new globals

    # Double-check if already running
    with server_management_lock:
        if server_process and server_process.poll() is None:
            print("_start_server_process: Server already running, skipping.")
            return True

    command = [] # Initialize empty command list
    target_path = None

    # --- Determine command based on START_MODE --- <<< MODIFY THIS SECTION
    if START_MODE == 'jar':
        target_path = MINECRAFT_SERVER_PATH / SERVER_JAR_NAME
        if not target_path.is_file():
            print(f"_start_server_process Error (JAR Mode): Server JAR not found at: {target_path}")
            return False
        command = [JAVA_EXECUTABLE] + JAVA_ARGS + ["-jar", str(target_path), "nogui"]
        print(f"_start_server_process: Starting server (JAR Mode) with command: {' '.join(command)}")

    elif START_MODE == 'script':
        target_path = MINECRAFT_SERVER_PATH / SERVER_SCRIPT_NAME
        if not target_path.is_file():
            print(f"_start_server_process Error (Script Mode): Server script not found at: {target_path}")
            return False
        if not os.access(target_path, os.X_OK): # Check if script is executable
             print(f"_start_server_process Warning (Script Mode): Server script '{target_path}' is not executable. Attempting 'bash {target_path}'...")
             # Optionally, try to make it executable:
             # try:
             #     target_path.chmod(target_path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
             #     print(f"_start_server_process: Made script '{target_path}' executable.")
             # except OSError as e:
             #     print(f"_start_server_process Error: Could not make script executable: {e}")
             #     # Decide how to proceed - maybe still try bash or fail?
             #     # For now, we proceed with bash assuming it might work.

        # Determine how to run the script - directly or via interpreter
        # Simple approach: assume bash for .sh, execute directly otherwise
        # More robust: Check shebang or rely on system PATH
        if str(target_path).lower().endswith('.sh'):
             command = ["bash", str(target_path)]
        else:
             # Attempt direct execution, relies on script being executable and having correct shebang
             command = [str(target_path)]
        print(f"_start_server_process: Starting server (Script Mode) with command: {' '.join(command)}")

    else:
        print(f"_start_server_process Error: Invalid START_MODE '{START_MODE}'. Check manager_settings.json.")
        return False
    # --- End of command determination ---

    new_process = None
    try:
        print(f"_start_server_process: Working directory: {MINECRAFT_SERVER_PATH}")
        preexec_fn = os.setsid if os.name != 'nt' else None
        new_process = subprocess.Popen(
            command, # Use the dynamically determined command
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
        print(f"_start_server_process: Server process initiated with PID: {new_process.pid}")

        # Short delay to check for immediate crash
        time.sleep(2)
        if new_process.poll() is not None:
            stderr_output = "N/A"
            try: stderr_output = new_process.stderr.read()
            except Exception: pass
            print(f"_start_server_process Error: Server process terminated quickly after launch.")
            print(f"_start_server_process Exit Code: {new_process.returncode}")
            print(f"_start_server_process Stderr (if available): {stderr_output[:500]}...")
            return False
        else:
            with server_management_lock:
                server_process = new_process
                user_initiated_stop = False
            print("_start_server_process: Server launch sequence initiated successfully.")
            return True

    except FileNotFoundError:
        # Error message depends on mode
        executable = command[0] if command else "(Unknown)"
        print(f"_start_server_process Error: Command '{executable}' not found. Is it installed and in PATH?")
        return False
    except Exception as e:
        print(f"_start_server_process Error: Failed to start server process: {e}")
        if new_process and new_process.poll() is None:
            try: new_process.kill(); new_process.wait(timeout=5)
            except: pass
        return False

# --- IMPORTANT ---
# Apply similar START_MODE checks and command construction logic within:
# 1. `try_start_server_on_launch()`
# 2. The `start_server()` route function
# Ensure they also use the correct command list based on the START_MODE setting.

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

            # Handle checkboxes (booleans) - value is 'on' if checked, None otherwise
            if isinstance(DEFAULT_SETTINGS[key], bool):
                updated_settings[key] = (form_value == 'on')
            # Handle numbers (int/float)
            elif isinstance(DEFAULT_SETTINGS[key], int):
                try:
                    updated_settings[key] = int(form_value)
                except (ValueError, TypeError):
                    form_errors.append(f"Invalid integer value for {key}: '{form_value}'")
                    # Keep old value on error, or set default? Let's keep old.
            elif isinstance(DEFAULT_SETTINGS[key], float):
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
                 else:
                     updated_settings[key] = [] # Empty list if form value is missing
            # Handle strings (default case)
            else:
                updated_settings[key] = form_value if form_value is not None else DEFAULT_SETTINGS[key]

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
                global JAVA_ARGS, MAX_LOG_LINES, ALLOWED_VIEW_EXTENSIONS, MAX_VIEW_FILE_SIZE_MB
                global ALLOWED_UPLOAD_EXTENSIONS, ALLOWED_EDIT_EXTENSIONS, RESTART_DELAY_SECONDS

                AUTOSTART_SERVER = updated_settings.get('AUTOSTART_SERVER', DEFAULT_SETTINGS['AUTOSTART_SERVER'])
                ENABLE_AUTO_RESTART_ON_CRASH = updated_settings.get('ENABLE_AUTO_RESTART_ON_CRASH', DEFAULT_SETTINGS['ENABLE_AUTO_RESTART_ON_CRASH'])
                SERVER_JAR_NAME = updated_settings.get('SERVER_JAR_NAME', DEFAULT_SETTINGS['SERVER_JAR_NAME'])
                JAVA_EXECUTABLE = updated_settings.get('JAVA_EXECUTABLE', DEFAULT_SETTINGS['JAVA_EXECUTABLE'])
                JAVA_ARGS = updated_settings.get('JAVA_ARGS', DEFAULT_SETTINGS['JAVA_ARGS'])
                MAX_LOG_LINES = updated_settings.get('MAX_LOG_LINES', DEFAULT_SETTINGS['MAX_LOG_LINES'])
                ALLOWED_VIEW_EXTENSIONS = set(updated_settings.get('ALLOWED_VIEW_EXTENSIONS', DEFAULT_SETTINGS['ALLOWED_VIEW_EXTENSIONS']))
                MAX_VIEW_FILE_SIZE_MB = updated_settings.get('MAX_VIEW_FILE_SIZE_MB', DEFAULT_SETTINGS['MAX_VIEW_FILE_SIZE_MB'])
                ALLOWED_UPLOAD_EXTENSIONS = set(updated_settings.get('ALLOWED_UPLOAD_EXTENSIONS', DEFAULT_SETTINGS['ALLOWED_UPLOAD_EXTENSIONS']))
                ALLOWED_EDIT_EXTENSIONS = set(updated_settings.get('ALLOWED_EDIT_EXTENSIONS', DEFAULT_SETTINGS['ALLOWED_EDIT_EXTENSIONS']))
                RESTART_DELAY_SECONDS = updated_settings.get('RESTART_DELAY_SECONDS', DEFAULT_SETTINGS['RESTART_DELAY_SECONDS'])

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
    return render_template('server_settings.html',
                           settings=manager_settings,
                           default_settings=DEFAULT_SETTINGS)

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
    """Starts the Minecraft server subprocess based on START_MODE."""
    # Use the already modified _start_server_process which handles START_MODE check
    global START_MODE # Ensure START_MODE is accessible

    if is_server_running():
        flash("Server is already running.", "warning")
        return redirect(url_for('index'))

    print(f"Start route: Attempting server start using mode: {START_MODE}")

    if _start_server_process(): # Call the internal function that has the correct logic
        flash(f"Server starting (Mode: {START_MODE})...", "success")
        time.sleep(4) # Give it a moment to spin up/potentially crash
    else:
        # _start_server_process already prints detailed errors
        flash(f"Server failed to start (Mode: {START_MODE}). Check manager logs for details.", "error")
        # _start_server_process sets server_process to None on failure

    return redirect(url_for('index'))


@app.route('/stop', methods=['POST'])
@login_required
def stop_server():
    """Stops the Minecraft server using stdin 'stop', with fallback (thread-safe)."""
    global server_process, user_initiated_stop

    with server_management_lock: # Acquire lock for duration of stop attempt
        if not server_process or server_process.poll() is not None:
            flash("Server is not running.", "warning")
            server_process = None # Ensure it's clear if already stopped
            user_initiated_stop = True # Treat as intentional stop even if already stopped
            return redirect(url_for('index'))

        # --- Set the flag BEFORE attempting to stop ---
        user_initiated_stop = True
        print("Stop route: User initiated stop flag SET.")
        # ---------------------------------------------

        current_process = server_process # Local reference within lock
        stopped_cleanly = False

        # 1. Try graceful shutdown via stdin
        try:
            print("Sending 'stop' command via stdin...")
            if current_process.stdin and not current_process.stdin.closed:
                current_process.stdin.write("stop\n")
                current_process.stdin.flush()
                flash("Stop command sent via stdin.", "info") # Changed to info, success on confirmation
                # Wait for the process to terminate after sending 'stop'
                try:
                    current_process.wait(timeout=20) # Generous timeout for MC shutdown
                    print("Server process stopped gracefully after stdin 'stop'.")
                    flash("Server stopped gracefully.", "success")
                    stopped_cleanly = True
                except subprocess.TimeoutExpired:
                    print("Server did not stop gracefully via stdin within timeout.")
                    flash("Server did not stop via stdin within 20s, attempting force.", "warning")
                except Exception as wait_err: # Catch other potential errors during wait
                     print(f"Error waiting for server process after stop command: {wait_err}")
                     flash("Error waiting for server shutdown, attempting force.", "warning")
            else:
                print("Server process stdin closed or unavailable.")
                flash("Could not send 'stop' (stdin unavailable). Attempting force.", "warning")
        except (OSError, BrokenPipeError) as e:
            print(f"Error writing 'stop' to stdin: {e}")
            flash(f"Error sending stop command ({e}). Attempting force.", "warning")
        except Exception as e: # Catch unexpected errors during stdin write/flush
            print(f"Unexpected error sending 'stop' command: {e}")
            flash(f"Unexpected error during stop command ({e}). Attempting force.", "warning")

        # 2. Force termination if necessary (still holding lock)
        # Check again if process exists and hasn't terminated on its own
        if not stopped_cleanly and current_process and current_process.poll() is None:
            flash("Attempting forceful termination.", "warning")
            try:
                pid_to_terminate = current_process.pid
                print(f"Terminating server process group (PID: {pid_to_terminate})...")

                # Try SIGTERM first (more graceful kill) using process group
                killed = False
                if os.name != 'nt' and hasattr(os, 'killpg') and hasattr(os, 'getpgid'):
                    try:
                        pgid = os.getpgid(pid_to_terminate)
                        os.killpg(pgid, signal.SIGTERM)
                        print(f"Sent SIGTERM to process group {pgid}.")
                    except ProcessLookupError:
                        print("Process group already gone before SIGTERM.")
                        killed = True # Already stopped
                    except Exception as kill_err:
                        print(f"Error sending SIGTERM to process group: {kill_err}. Falling back to terminate().")
                        current_process.terminate() # Fallback to single process terminate
                else: # Windows or fallback
                    print("Sending SIGTERM via terminate().")
                    current_process.terminate()

                # Wait for termination after SIGTERM/terminate()
                if not killed:
                    try:
                        current_process.wait(timeout=10)
                        print("Server process terminated after SIGTERM/terminate().")
                        flash("Server process terminated.", "success")
                        killed = True
                    except subprocess.TimeoutExpired:
                        print("Server process did not terminate after SIGTERM/terminate(), sending SIGKILL.")
                        flash("Server process unresponsive, forcing kill.", "warning")
                    except Exception as term_wait_err:
                         print(f"Error waiting after SIGTERM/terminate: {term_wait_err}")
                         flash("Error waiting for termination, attempting force kill.", "warning")

                # Send SIGKILL if still alive (force kill)
                if not killed and current_process.poll() is None:
                    if os.name != 'nt' and hasattr(os, 'killpg') and hasattr(os, 'getpgid'):
                        try:
                            pgid = os.getpgid(pid_to_terminate) # Get pgid again just in case
                            os.killpg(pgid, signal.SIGKILL)
                            print(f"Sent SIGKILL to process group {pgid}.")
                        except ProcessLookupError:
                             print("Process group already gone before SIGKILL.")
                        except Exception as kill_err:
                             print(f"Error sending SIGKILL to process group: {kill_err}. Falling back to kill().")
                             current_process.kill() # Fallback to single process kill
                    else: # Windows or fallback
                        print("Sending SIGKILL via kill().")
                        current_process.kill()

                    try:
                        current_process.wait(timeout=5) # Should die quickly after SIGKILL
                        print("Server process killed.")
                        flash("Server process killed.", "success")
                    except subprocess.TimeoutExpired:
                         print("Error: Server process failed to die even after SIGKILL!")
                         flash("CRITICAL: Failed to kill server process!", "error")
                    except Exception as kill_wait_err:
                         print(f"Error waiting after SIGKILL: {kill_wait_err}")
                         flash("Error waiting after kill signal.", "error")

            except ProcessLookupError: # If process disappeared during the forceful stop logic
                flash("Server process stopped during termination attempt.", "info")
            except Exception as e:
                print(f"Error during forceful termination: {e}")
                flash(f"Error terminating server process: {e}.", "error")

        # --- Finally, clear the global process variable ---
        # This happens regardless of how it stopped, as the intent was to stop.
        print("Stop route: Clearing global server_process handle.")
        server_process = None
        # user_initiated_stop remains True

    # Lock is released automatically upon exiting 'with' block
    return redirect(url_for('index'))

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

        return render_template(template_name,
                               filename=full_path.name,
                               filepath=filepath, # Pass relative path
                               content=content,
                               mimetype=mimetype,
                               can_edit=can_edit # Pass edit flag to template
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
    """Upload a file to the specified directory."""
    target_rel_dir = request.form.get('target_dir', '')
    redirect_target = url_for('files', subpath=target_rel_dir)

    target_full_dir = get_full_path(target_rel_dir) if target_rel_dir else MINECRAFT_SERVER_PATH
    if target_full_dir is None or not target_full_dir.is_dir():
        flash(f"Invalid upload directory '{target_rel_dir}'.", "error"); return redirect(url_for('files')) # Redirect to root on error

    if 'file' not in request.files: flash('No file part.', "error"); return redirect(redirect_target)
    file = request.files['file']
    if not file or file.filename == '': flash('No selected file.', "warning"); return redirect(redirect_target)

    if allowed_file(file.filename):
        filename = secure_filename(file.filename)
        if not filename: flash('Invalid file name after sanitizing.', "error"); return redirect(redirect_target)

        destination_path = target_full_dir / filename
        # Check safety of final destination path
        if not is_safe_path(destination_path): flash("Upload destination path is invalid/unsafe.", "error"); return redirect(redirect_target)
        if destination_path.exists(): flash(f"File '{filename}' already exists. Upload cancelled.", "error"); return redirect(redirect_target)

        try:
            # Consider size limit enforcement *before* saving if possible/needed
            file.save(destination_path)
            flash(f"File '{filename}' uploaded to '{target_rel_dir or 'root'}'.", "success")
        except PermissionError: flash(f"Permission denied to upload to '{target_rel_dir}'.", "error")
        except Exception as e:
            error_msg = f"Error saving file: {e}"
            # Check if it's Flask's RequestEntityTooLarge exception
            if 'RequestEntityTooLarge' in str(type(e)):
                error_msg = f"Upload failed: File exceeds maximum size limit ({MAX_UPLOAD_SIZE_MB} MB)."
            print(f"Upload save error: {e}"); flash(error_msg, "error")

        return redirect(redirect_target)
    else:
        allowed_ext_str = ', '.join(ALLOWED_UPLOAD_EXTENSIONS)
        flash(f'File type not allowed. Allowed types: {allowed_ext_str}', "error")
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


# --- API Routes --- (Apply @login_required)

@app.route('/status_api')
@login_required
def status_api():
    """API endpoint to get server status."""
    return jsonify(status="Running" if is_server_running() else "Stopped")

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

    app.run(debug=False, host='127.0.0.1', port=8080) # Keep debug=True for development
