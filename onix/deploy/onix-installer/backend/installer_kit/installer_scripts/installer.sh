#!/bin/bash
# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


# This script orchestrates the initial setup for the BECKN adapter installation,
# handling user authentication and service account configuration.

# Exit immediately if a command exits with a non-zero status.
set -e

# --- Helper Functions ---
# Function to check if a command exists
check_command() {
    if ! command -v "$1" &> /dev/null; then
        return 1
    else
        return 0
    fi
}

# Function to validate all prerequisites
validate_prerequisites() {
    echo "--- Checking prerequisites ---"
    local missing_prereqs=()
    local prereq_script_path="./backend/installer_kit/installer_scripts/install_preqreqs.sh"
    local prereqs=("gcloud" "terraform" "helm" "kubectl" "gsutil" "jq" "gke-gcloud-auth-plugin" "psql" "python3" "node" "ng")

    for prereq in "${prereqs[@]}"; do
        if ! check_command "$prereq"; then
            missing_prereqs+=("$prereq")
        fi
    done

    if [ ${#missing_prereqs[@]} -ne 0 ]; then
        echo "Warning: The following required tools are not installed: ${missing_prereqs[*]}"
        read -p "Press 'Y' to attempt installation or 'N' to exit. (y/N) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            if [ -f "$prereq_script_path" ]; then
                echo "Running installation script from $prereq_script_path..."
                bash "$prereq_script_path"

                # Re-validate after installation attempt
                echo "--- Re-checking prerequisites after installation ---"
                local still_missing=()
                for prereq in "${prereqs[@]}"; do
                    if ! check_command "$prereq"; then
                        still_missing+=("$prereq")
                    fi
                done

                if [ ${#still_missing[@]} -ne 0 ]; then
                    echo "Error: The following prerequisites could not be installed automatically: ${still_missing[*]}"
                    echo "Please install them manually and re-run the script."
                    exit 1
                fi
            else
                echo "Error: Prerequisite installation script not found at $prereq_script_path"
                exit 1
            fi
        else
            echo "Prerequisites not met. Exiting."
            exit 1
        fi
    fi
    echo "All prerequisites are installed."
    echo "--------------------------"
    echo
}

PROJECT_ROOT="./"
BACKEND_DIR="$PROJECT_ROOT/backend"
FRONTEND_DIR="$PROJECT_ROOT/frontend"


cleanup() {
    echo
    echo "--- Shutting Down Installer ---"

    # Find and kill the frontend and backend processes
    if command -v pkill &> /dev/null; then
        echo "Stopping frontend server (ng serve)..."
        pkill -f "ng serve" || echo "Frontend server was not running."
        echo "Stopping backend server (uvicorn)..."
        pkill -f "uvicorn main:app" || echo "Backend server was not running."
    else
        echo "pkill not found, falling back to lsof to find processes by port."
        echo "Stopping frontend server (on port 4200)..."
        lsof -t -i:4200 | xargs -r kill
        echo "Stopping backend server (on port 8000)..."
        lsof -t -i:8000 | xargs -r kill
    fi

    # Deactivate Python virtual environment if it was activated
    if [ -d "$BACKEND_DIR/venv" ]; then
        echo "Deactivating Python virtual environment..."
        if [[ "$VIRTUAL_ENV" == "$BACKEND_DIR/venv" ]]; then
            deactivate || echo "Virtual environment was not active."
        else
            echo "Virtual environment was not active in this shell."
        fi
    fi

    echo "To stop impersonating the service account, run:"
    echo "  gcloud auth application-default revoke"
    echo "-------------------------------"
    echo "Shutdown complete."
}

# Trap EXIT signal to run the cleanup function
trap cleanup EXIT

# --- Main Script ---

# 1. Prerequisite Validation
validate_prerequisites

# 2. Google Cloud User Authentication
echo "--- Step 1: Google Cloud Authentication ---"
gcloud auth login
echo "Authentication successful."
echo "-------------------------------------------"
echo

# 3. Service Account Configuration
echo "--- Step 2: Service Account Configuration ---"
SA_EMAIL=""
read -p "Do you already have a service account with the required permissions? (y/N) " -n 1 -r
echo # Move to a new line

if [[ $REPLY =~ ^[Yy]$ ]]; then
    # User has an existing service account
    while [ -z "$SA_EMAIL" ]; do
        read -p "Enter the email of the service account to use: " SA_EMAIL
        if [ -z "$SA_EMAIL" ]; then
            echo "Service account email cannot be empty. Please try again."
        fi
    done
else
    # User needs to create a new service account
    echo "A service account is required to provision resources."
    echo "The script to create a new service account will now be executed."

    CREATE_SA_SCRIPT="./backend/installer_kit/installer_scripts/create_service_account.sh"

    if [ ! -f "$CREATE_SA_SCRIPT" ]; then
        echo "Error: The service account creation script ($CREATE_SA_SCRIPT) was not found."
        exit 1
    fi

    SA_EMAIL=$(bash "$CREATE_SA_SCRIPT")

    echo
    echo "The service account has been created successfully."
fi

echo
echo "Will proceed using service account: $SA_EMAIL"
echo "-------------------------------------------"
echo

# 4. Impersonation for Terraform and other tools
echo "--- Step 3: Setting up Service Account Impersonation ---"
echo "Configuring Application Default Credentials (ADC) to impersonate $SA_EMAIL."
gcloud auth application-default login --impersonate-service-account="$SA_EMAIL"
echo "Impersonation configured successfully."
echo "--------------------------------------------------------"
echo
echo "✅ Initial setup complete."



# Create a logs directory
LOG_DIR="$PROJECT_ROOT/logs"
mkdir -p "$LOG_DIR"
echo "📝 Logs will be stored in the $LOG_DIR directory."

LOG_DIR="$(cd "$LOG_DIR" && pwd)"

if [ -d "$FRONTEND_DIR" ]; then
    echo "🔵 Installing frontend dependencies and starting server..."
    (cd "$FRONTEND_DIR" && npm install > "$LOG_DIR/frontend-install.log" 2>&1 && ng serve > "$LOG_DIR/frontend.log" 2>&1 &)
    echo "✅ Frontend server started. View logs at $LOG_DIR/frontend.log"
else
    echo "⚠️  Warning: Frontend directory not found at $FRONTEND_DIR. Skipping."
fi

if [ -d "$BACKEND_DIR" ] && [ -f "$BACKEND_DIR/main.py" ]; then
       echo "🚀 Setting up backend virtual environment and starting server..."
    (
        cd "$BACKEND_DIR" || exit 1 # Change to backend directory, exit if fails

        # Create venv inside backend directory
        echo "Creating virtual environment in $BACKEND_DIR/venv..."
        python3 -m venv venv

        # Activate venv
        echo "Activating virtual environment..."
        source venv/bin/activate

        # Install backend dependencies
        echo "Installing backend dependencies from requirements.txt..."
        pip3 install -r requirements.txt --require-hashes > "$LOG_DIR/backend-install.log" 2>&1

        # Start backend server
        echo "Starting backend server..."
        uvicorn main:app --reload > "$LOG_DIR/backend.log" 2>&1 &

        # Store the PID of uvicorn for potential future use in cleanup if needed
        # (though pkill -f is generally sufficient)
        echo "$!" > "$LOG_DIR/backend_uvicorn.pid"

        echo "✅ Backend server started. (Typically at http://localhost:8000). View logs at $LOG_DIR/backend.log"
    ) & # Run the entire backend setup in a subshell in the background
   else
    echo "⚠️  Could not start backend. Directory or main.py not found in $BACKEND_DIR."
fi

# --- Open Installer UI in Browser ---
echo
echo "--- Step 4: Opening Installer UI ---"
echo "Giving the servers a moment to start..."
sleep 8

URL="http://localhost:4200"

# Check OS and open browser
if [[ "$(uname)" == "Darwin" ]]; then
  open "$URL"
elif [[ "$(uname)" == "Linux" ]]; then
  xdg-open "$URL"
elif [[ "$OSTYPE" == "cygwin" || "$OSTYPE" == "msys" || "$OSTYPE" == "win32" ]]; then
  cmd.exe /c start "$URL"
else
  echo "Could not detect OS to automatically open browser."
  echo "Please open the installer UI manually at $URL"
fi
echo "------------------------------------"
echo

# --- Wait for user to exit ---
echo "✅ Installer is running. Press [Enter] to shut down all services and exit."
read