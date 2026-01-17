#!/usr/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e
# Treat unset variables as an error when substituting.
set -u
# Pipelines return the exit status of the last command that failed, or zero if all succeeded.
set -o pipefail

# --- Configuration ---
APP_NAME="MSMP"
VENV_DIR="$HOME/.local/share/${APP_NAME}" # Virtual environment location
APP_INSTALL_DIR="${VENV_DIR}/app" # Where the Flask app files will live inside the venv
TARGET_BIN_DIR="/usr/local/bin"          # Standard location for user-installed executables
SOURCE_APP_DIR="./"
REQUIRED_ITEMS=(
    "${SOURCE_APP_DIR}/app.py"
    "${SOURCE_APP_DIR}/static"
    "${SOURCE_APP_DIR}/templates"
)
PYTHON_DEPS=(
    "pip"
    "setuptools"
    "wheel"
    "Flask"
    "flask-socketio"
    "eventlet"
)
MAIN_EXECUTABLE_NAME="msmp"
LINK_NAMES=( "msmp" )

# --- Helper Functions ---
info() {
    echo "[INFO] $1"
}

warn() {
    echo "[WARN] $1" >&2
}

error() {
    echo "[ERROR] $1" >&2
    exit 1
}

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

run_sudo() {
    if [[ $EUID -eq 0 ]]; then
        "$@"
    elif command_exists sudo; then
        sudo "$@"
    else
        error "sudo command not found. Cannot perform required action: $*"
    fi
}

# --- Core Functions ---

install_system_deps() {
    info "Checking/Installing system dependencies..."
    if command_exists apt; then
        run_sudo apt update
        run_sudo apt install -y python3 python3-venv || error "Failed using apt."
    elif command_exists dnf; then
        run_sudo dnf install -y python3 python3-virtualenv || error "Failed using dnf."
    elif command_exists pacman; then
        run_sudo pacman -S --noconfirm --needed python python-virtualenv || error "Failed using pacman."
    elif command_exists emerge; then
        run_sudo emerge --ask --noreplace dev-lang/python || error "Failed emerge."
    else
        warn "Could not detect package manager. Ensure Python 3 and venv are installed."
    fi
}

full_install() {
    info "Starting full installation..."

    # Cleanup old
    if [[ -d "${VENV_DIR}" ]]; then
        info "Removing old virtual environment..."
        rm -rf "${VENV_DIR}"
    fi

    install_system_deps

    # Create Venv
    info "Creating virtual environment in ${VENV_DIR}"
    mkdir -p "$(dirname "${VENV_DIR}")"
    python3 -m venv "${VENV_DIR}" || error "Failed to create venv."

    # Install Python Deps
    source "${VENV_DIR}/bin/activate"
    info "Installing Python dependencies..."
    python -m pip install --upgrade pip
    python -m pip install "${PYTHON_DEPS[@]}"
    deactivate

    # Copy App Files
    info "Copying application files..."
    mkdir -p "${APP_INSTALL_DIR}"
    cp "${SCRIPT_DIR}/${SOURCE_APP_DIR}/app.py" "${APP_INSTALL_DIR}/"
    cp -r "${SCRIPT_DIR}/${SOURCE_APP_DIR}/static" "${APP_INSTALL_DIR}/"
    cp -r "${SCRIPT_DIR}/${SOURCE_APP_DIR}/templates" "${APP_INSTALL_DIR}/"
    
    # Manager settings (if exists source, copy) - User requested not to overwrite, but this is full install
    # Assuming start fresh for config on full install OR preserve?
    # Usually full install implies fresh. But let's check for existing config backup?
    # For now, standard full install.
    
    # Install Executable
    info "Installing executable..."
    run_sudo cp "${SCRIPT_DIR}/msmp" "${TARGET_BIN_DIR}/${MAIN_EXECUTABLE_NAME}"
    run_sudo chmod +x "${TARGET_BIN_DIR}/${MAIN_EXECUTABLE_NAME}"

    info "Full installation complete."
}

update_app() {
    info "Updating application files only..."
    
    # Check Venv
    if [[ ! -d "${APP_INSTALL_DIR}" ]]; then
        error "Application directory not found at ${APP_INSTALL_DIR}. Use full install."
    fi

    # Update app.py
    cp "${SCRIPT_DIR}/${SOURCE_APP_DIR}/app.py" "${APP_INSTALL_DIR}/" || error "Failed to update app.py"

    # Update static (Replace directory but keep other files? No, static is usually code assets)
    # Safest is to remove OLD static folder and copy NEW one.
    rm -rf "${APP_INSTALL_DIR}/static"
    cp -r "${SCRIPT_DIR}/${SOURCE_APP_DIR}/static" "${APP_INSTALL_DIR}/" || error "Failed to update static"

    # Update templates
    rm -rf "${APP_INSTALL_DIR}/templates"
    cp -r "${SCRIPT_DIR}/${SOURCE_APP_DIR}/templates" "${APP_INSTALL_DIR}/" || error "Failed to update templates"

    info "Update complete. Database and Settings preserved."
}

create_service() {
    SERVICE_NAME="msmp"
    SERVICE_PATH="/etc/systemd/system/${SERVICE_NAME}.service"
    
    # Determine user to run as
    REAL_USER="${SUDO_USER:-$USER}"
    
    info "Setting up systemd service '${SERVICE_NAME}' for user '${REAL_USER}'..."

    # Create temporary service file
    cat <<EOF > /tmp/${SERVICE_NAME}.service
[Unit]
Description=Minecraft Server Manager Panel
After=network.target

[Service]
Type=simple
User=${REAL_USER}
ExecStart=${TARGET_BIN_DIR}/${MAIN_EXECUTABLE_NAME}
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

    # Install
    run_sudo mv /tmp/${SERVICE_NAME}.service "${SERVICE_PATH}"
    run_sudo systemctl daemon-reload
    info "Service file created at ${SERVICE_PATH}"

    # Prompt Enable
    read -p "Enable service to start on boot? (y/N): " ENABLE_OPT
    if [[ "$ENABLE_OPT" =~ ^[Yy]$ ]]; then
        run_sudo systemctl enable "${SERVICE_NAME}"
        info "Service enabled."
    fi

    # Prompt Start
    read -p "Start service now? (y/N): " START_OPT
    if [[ "$START_OPT" =~ ^[Yy]$ ]]; then
        run_sudo systemctl start "${SERVICE_NAME}"
        info "Service started."
        run_sudo systemctl status "${SERVICE_NAME}" --no-pager
    fi
}


# --- Main Logic ---

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

# Check Source Items
for item in "${REQUIRED_ITEMS[@]}"; do
    if [[ ! -e "${SCRIPT_DIR}/${item}" ]]; then
        error "Required source item not found: ${item}"
    fi
done

if [[ -d "${VENV_DIR}" ]]; then
    # Existing install detected
    echo "Existing installation found at ${VENV_DIR}."
    echo "1) Update (only updates app code, preserves data)"
    echo "2) Reinstall (wipes existing venv and app data, FRESH install)"
    echo "3) Cancel"
    read -p "Select option [1]: " OPTION
    OPTION=${OPTION:-1}

    case $OPTION in
        1)
            update_app
            ;;
        2)
            read -p "Are you sure you want to delete everything and reinstall? (y/N): " CONFIRM
            if [[ "$CONFIRM" =~ ^[Yy]$ ]]; then
                full_install
            else
                info "Reinstall cancelled."
                exit 0
            fi
            ;;
        *)
            info "Cancelled."
            exit 0
            ;;
    esac
else
    # New install
    full_install
fi

# Service Setup Check (Only on Linux with systemd)
if command_exists systemctl; then
    if [[ -f "/etc/systemd/system/msmp.service" ]]; then
        echo "Systemd service 'msmp' detected."
    else
        echo ""
        read -p "Create systemd service for auto-start? (y/N): " SERVICE_OPT
        if [[ "$SERVICE_OPT" =~ ^[Yy]$ ]]; then
            create_service
        fi
    fi
fi

echo "Done."
exit 0
