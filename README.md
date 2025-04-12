# Minecraft Server Management Panel
# Requirements
### Java (Version depends on what mc version you'll use)
### Git
### Python & venv (Installed with the install script)
# Key features
### File Manager over the web
### Server Properties over the web
### Panel Config over the web
### User Accounts. (Please disable registration in "Panel Settings" after registering.)
### Receive console logs over the web
### Send console commands over the web
### File Editor over the web
### And more...


# Installation Guide

> Follow the steps below to install and set up MSMP on your linux system.
# 1. Install Git

Debian Based:

> sudo apt-get install git

Fedora Based:

> sudo dnf install git

Arch Linux Based:

> sudo pacman -S git

Gentoo Based:

> sudo emerge dev-vcs/git

# 2. Clone the Repository

Once Git is installed, clone the MSMP repository by running the following command:

> git clone https://github.com/Nakildias/MSMP

# 3. Navigate to the Project Directory

Change into the newly created MSMP directory:

> cd MSMP

# 4. Install MSMP

Inside the MSMP directory, run the installation script:

> bash ./install.sh

# 5. Enter Your Sudo Password

> The script will prompt you for your sudo password. Enter it to proceed with the installation.

# 6. Run MSMP with this command:

> msmp

# 7. Configuration (Recommended)

> By default, MSMP runs on port 8080 and registration is enabled.

If you’d like to change the default settings port, you can edit:

> ~/.local/share/MSMP/app/app.py
### Port in on the last line: app.run(debug=False, host='127.0.0.1', port=8080)

Use any text editor of your choice to modify these values sudo/root not required.

  
