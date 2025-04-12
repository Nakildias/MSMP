#!/usr/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e
# Treat unset variables as an error when substituting.
set -u
# Pipelines return the exit status of the last command that failed, or zero if all succeeded.
set -o pipefail

# --- Configuration ---
APP_NAME="MSMP" # Updated App Name
VENV_DIR="$HOME/.local/share/${APP_NAME}" # Virtual environment location
APP_INSTALL_DIR="${VENV_DIR}/app" # Where the Flask app files will live inside the venv
TARGET_BIN_DIR="/usr/local/bin"          # Standard location for user-installed executables
# Source directories/files relative to the script location
# Assumes install.sh is in the parent directory of MSMP
SOURCE_APP_DIR="./"
REQUIRED_ITEMS=( # Items needed from the source directory
    "${SOURCE_APP_DIR}/app.py"
    "${SOURCE_APP_DIR}/static"
    "${SOURCE_APP_DIR}/templates"
    # Add manager_settings.json if you want to ship a default one
    # "${SOURCE_APP_DIR}/manager_settings.json"
)
PYTHON_DEPS=( # Python packages to install via pip
    "pip" # Ensure pip is up-to-date first
    "setuptools"
    "wheel"
    "Flask" # Main dependency for the web app
    # Werkzeug is installed as a Flask dependency
)
MAIN_EXECUTABLE_NAME="msmp" # Name of the script to link in TARGET_BIN_DIR
LINK_NAMES=( "msmp" ) # Additional names (symlinks)

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

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to run command with sudo, prompting if needed
run_sudo() {
    if [[ $EUID -eq 0 ]]; then
        "$@" # Already root, just run it
    elif command_exists sudo; then
        info "Requesting sudo privileges for: $*"
        sudo "$@"
    else
        error "sudo command not found. Cannot perform required action: $*"
    fi
}

# --- Pre-flight Checks ---

# Check if running as root - inform user sudo will be requested as needed.
if [ "$EUID" -eq 0 ]; then
 warn "Running as root. While not recommended, the script will proceed."
 warn "Consider running as a regular user; sudo will be requested when needed."
fi

# Determine the directory where the script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
info "Script source directory: ${SCRIPT_DIR}"

# Check if source items exist relative to the script directory
for item in "${REQUIRED_ITEMS[@]}"; do
    item_path="${SCRIPT_DIR}/${item}"
    if [[ ! -e "${item_path}" ]]; then # Check if file or directory exists
        error "Required source item not found: ${item_path}"
    fi
done

# --- System Dependency Installation (Always Run) ---

info "Attempting to install/update system dependencies (Python 3, venv)..."
PACKAGE_MANAGER=""

if command_exists apt; then
    PACKAGE_MANAGER="apt"
    run_sudo apt update # Update package list first
    run_sudo apt install -y python3 python3-venv || error "Failed using apt."
elif command_exists dnf; then
    PACKAGE_MANAGER="dnf"
    run_sudo dnf install -y python3 python3-virtualenv || error "Failed using dnf."
elif command_exists pacman; then
    PACKAGE_MANAGER="pacman"
    run_sudo pacman -S --noconfirm --needed python python-virtualenv || error "Failed using pacman."
elif command_exists emerge; then
     PACKAGE_MANAGER="emerge"
     # Gentoo typically includes venv with python, but check for python itself
     run_sudo emerge --ask --noreplace dev-lang/python || error "Failed initial emerge for python."
     info "Assuming Python 3 venv module is included with dev-lang/python on Gentoo."
else
    error "Could not detect a supported package manager (apt, dnf, pacman, emerge). Please install Python 3 and the Python venv module manually."
fi

info "System dependency check/installation complete."

# Double check python3 and venv module after attempting install
if ! command_exists python3; then
    error "Python 3 installation failed or python3 is not in PATH."
fi
# Check for venv module availability
if ! python3 -m venv --help >/dev/null 2>&1; then
    error "Python 3 'venv' module installation failed or is not available."
fi
info "Python 3 and venv module confirmed."


# --- Cleanup Previous Installation (if exists) ---

if [[ -d "${VENV_DIR}" ]]; then
    info "Existing installation found at ${VENV_DIR}. Reinstalling..."
    info "Removing old virtual environment..."
    rm -rf "${VENV_DIR}" || error "Failed to remove old virtual environment: ${VENV_DIR}"

    info "Removing old executable and links from ${TARGET_BIN_DIR}..."
    run_sudo rm -f "${TARGET_BIN_DIR}/${MAIN_EXECUTABLE_NAME}" || warn "Could not remove old executable (might not exist)."
    for link_name in "${LINK_NAMES[@]}"; do
        TARGET_LINK="${TARGET_BIN_DIR}/${link_name}"
        run_sudo rm -f "${TARGET_LINK}" || warn "Could not remove old symlink ${link_name} (might not exist)."
    done
    info "Previous installation cleanup complete."
else
    info "No previous installation found at ${VENV_DIR}. Proceeding with new installation."
fi

# --- Virtual Environment Setup & Application Installation (Always Run) ---

info "Creating Python virtual environment in ${VENV_DIR}"
mkdir -p "$(dirname "${VENV_DIR}")" || error "Failed to create parent directory for ${VENV_DIR}"
python3 -m venv "${VENV_DIR}" || error "Failed to create virtual environment."

info "Activating virtual environment for dependency installation (temporary)"
# Activate venv for pip commands - use source for bash compatibility
source "${VENV_DIR}/bin/activate" || error "Failed to activate virtual environment."

info "Upgrading pip..."
python -m pip install --upgrade pip || error "Failed to upgrade pip in venv."
pip install --upgrade setuptools wheel || error "Failed to upgrade setuptools/wheel."

info "Installing Python dependencies into virtual environment..."
python -m pip install "${PYTHON_DEPS[@]}" || error "Failed to install Python dependencies."

info "Deactivating virtual environment"
deactivate # Good practice to deactivate after use in script

info "Copying application files into virtual environment..."
mkdir -p "${APP_INSTALL_DIR}" || error "Failed to create app directory in venv: ${APP_INSTALL_DIR}"
cp "${SCRIPT_DIR}/${SOURCE_APP_DIR}/app.py" "${APP_INSTALL_DIR}/" || error "Failed to copy app.py"
cp -r "${SCRIPT_DIR}/${SOURCE_APP_DIR}/static" "${APP_INSTALL_DIR}/" || error "Failed to copy static directory"
cp -r "${SCRIPT_DIR}/${SOURCE_APP_DIR}/templates" "${APP_INSTALL_DIR}/" || error "Failed to copy templates directory"
# Add copy for default manager_settings.json if needed
# if [[ -f "${SCRIPT_DIR}/${SOURCE_APP_DIR}/manager_settings.json" ]]; then
#     cp "${SCRIPT_DIR}/${SOURCE_APP_DIR}/manager_settings.json" "${APP_INSTALL_DIR}/" || error "Failed to copy manager_settings.json"
# fi

info "Copying msmp executable to /usr/local/bin/"
sudo cp ./msmp /usr/local/bin/

# Copy the temporary file to the target destination using sudo and set permissions
run_sudo chmod +x "${TARGET_BIN_DIR}/${MAIN_EXECUTABLE_NAME}" || error "Failed to set executable permission."

# Create symlinks (remove first to ensure correctness)
for link_name in "${LINK_NAMES[@]}"; do
    # Only create if link name is different from main executable name
    if [[ "${link_name}" != "${MAIN_EXECUTABLE_NAME}" ]]; then
        TARGET_LINK="${TARGET_BIN_DIR}/${link_name}"
        info "Creating symlink: ${TARGET_LINK} -> ${MAIN_EXECUTABLE_NAME}"
        # Remove existing link first
        mkdir $VENV_DIR/app/Minecraft_Server
        run_sudo rm -f "${TARGET_LINK}" || warn "Could not remove potentially existing symlink ${TARGET_LINK}"
        run_sudo ln -sf "${TARGET_BIN_DIR}/${MAIN_EXECUTABLE_NAME}" "${TARGET_LINK}" || error "Failed to create symlink ${link_name}"
    fi
done

info "Installation steps completed."


# --- Final Check ---

# Check if the main executable file exists and is executable
if [[ -x "${TARGET_BIN_DIR}/${MAIN_EXECUTABLE_NAME}" ]]; then
    # Check if the command is found in the PATH
    if command_exists "${MAIN_EXECUTABLE_NAME}"; then
        info "-------------------------------------------"
        info " Installation successful!"
        info " Virtual Environment: ${VENV_DIR}"
        info " App Files: ${APP_INSTALL_DIR}"
        info " Executable: ${TARGET_BIN_DIR}/${MAIN_EXECUTABLE_NAME}"
        info " You should now be able to run the application using: ${MAIN_EXECUTABLE_NAME}"
        info " IMPORTANT: The application expects the Minecraft server directory"
        info "            to be located at './Minecraft_Server' relative to where"
        info "            you run the '${MAIN_EXECUTABLE_NAME}' command."
        info "            Alternatively, edit '${APP_INSTALL_DIR}/app.py' to set an absolute path."
        info " If the command isn't found immediately, try opening a new terminal session."
        info "-------------------------------------------"
    else
        warn "-------------------------------------------"
        warn " Installation seems complete, but '${MAIN_EXECUTABLE_NAME}' not found in current PATH."
        warn " Executable is located at: ${TARGET_BIN_DIR}/${MAIN_EXECUTABLE_NAME}"
        warn " Please ensure '${TARGET_BIN_DIR}' is in your PATH environment variable."
        warn " You might need to restart your shell, log out and back in, or manually add it."
        warn " Example (add to ~/.bashrc or ~/.zshrc): export PATH=\"${TARGET_BIN_DIR}:\$PATH\""
        warn "-------------------------------------------"
    fi
else
    error "Installation failed. Could not find executable file at '${TARGET_BIN_DIR}/${MAIN_EXECUTABLE_NAME}' or it lacks execute permissions."
fi

exit 0
