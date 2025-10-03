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


# Exit immediately if a command exits with a non-zero status.
set -e

# Configuration
TERRAFORM_FOLDERS=(
    "./backend/installer_kit/terraform/phase2" # Destroy this first
    "./backend/installer_kit/terraform"        # Destroy this second
)

# Array to track only the folders that have existing state and will be destroyed.
FOLDERS_TO_DESTROY=()


# Helper Function for Confirmation.
confirm_action() {
    read -r -p "$1 (y/N) " response
    case "$response" in
        [yY][eE][sS]|[yY])
            true
            ;;
        *)
            false
            ;;
    esac
}

# Helper function to get the tfvars file based on the folder path.
get_tfvars_file() {
    local folder_path="$1"
    case "$folder_path" in
        "./backend/installer_kit/terraform/phase2")
            echo "p2.tfvars"
            ;;
        "./backend/installer_kit/terraform")
            echo "generated-terraform.tfvars"
            ;;
        *)
            echo ""
            ;;
    esac
}

# Function to check if a Terraform state exists and contains resources.
check_state_exists() {
    # terraform state list returns an error if no state file is present, or a list of resources if it is.
    terraform state list 2>/dev/null | grep -q '.*'
}

echo "Generating Terraform Infrastructure Destruction Plans"
echo "Please review the resources that will be destroyed."
echo ""

# Create a temporary directory for all plan files.
TEMP_PLAN_DIR=$(mktemp -d)
echo "Temporary plan files will be stored in: $TEMP_PLAN_DIR"
echo ""

# Ensure the temporary directory is removed when the script exits,
# even if there's an error (using a trap).
trap 'echo "Cleaning up temporary directory: $TEMP_PLAN_DIR"; rm -rf "$TEMP_PLAN_DIR"' EXIT

# Arrays to store temporary plan file paths.
PLAN_FILES_TEXT=()
PLAN_FILES_BINARY=()

# Step 1: Generate Plans for Each Folder (if state exists)
for i in "${!TERRAFORM_FOLDERS[@]}"; do
    FOLDER_PATH="${TERRAFORM_FOLDERS[$i]}"
    TFVARS_FILE=$(get_tfvars_file "$FOLDER_PATH")

    echo "### Checking state for: $FOLDER_PATH ###"
    if [ -d "$FOLDER_PATH" ]; then
        cd "$FOLDER_PATH"
        terraform init

        # Check for existing state/resources
        if check_state_exists; then
            echo "✅ State file/tracked resources found. Proceeding with plan generation."
            FOLDERS_TO_DESTROY+=("$FOLDER_PATH")

            # Define temporary file names within the temporary directory.
            PLAN_TEXT_FILE="$TEMP_PLAN_DIR/plan_output_$i.txt"
            PLAN_BINARY_FILE="$TEMP_PLAN_DIR/plan_binary_$i.tfplan"

            PLAN_FILES_TEXT+=("$PLAN_TEXT_FILE")
            PLAN_FILES_BINARY+=("$PLAN_BINARY_FILE")

            echo -e "Generating Destroy plan for "$FOLDER_PATH" using $TFVARS_FILE"

            # Run plan and save output to temporary files.
            if ! terraform plan -destroy -var-file="$TFVARS_FILE" -out="$PLAN_BINARY_FILE" > "$PLAN_TEXT_FILE" 2>&1; then
                echo "ERROR: Failed to generate plan for $FOLDER_PATH. Review the error messages below."
                cat "$PLAN_TEXT_FILE" # Show the error output
                echo "---------------------------------------------------"
                exit 1 # Exit immediately on plan generation failure
            fi

            echo "Plan generated for $FOLDER_PATH. Review below."
            echo "---------------------------------------------------"
            cat "$PLAN_TEXT_FILE"
            echo "---------------------------------------------------"
            echo ""

        else
            echo "⚠️ No Terraform state or tracked resources found. Skipping destruction for $FOLDER_PATH."
        fi

        cd - > /dev/null
    else
        echo "ERROR: Folder '$FOLDER_PATH' not found. Exiting."
        exit 1
    fi
done
# --------------------------------------------------
echo "ALL DESTRUCTION PLANS SHOWN ABOVE"
echo ""

# Step 2: Confirmation
if [ ${#FOLDERS_TO_DESTROY[@]} -eq 0 ]; then
    echo "No Terraform state was found in any folder. Nothing to destroy."
    exit 0
fi

if confirm_action "Do you want to proceed with destroying ALL ${#FOLDERS_TO_DESTROY[@]} infrastructure components as planned above?"; then
    echo "Proceeding with Terraform Infrastructure Destruction"
    echo ""

    # Step 3: Execute Destroy for Each Folder
    for FOLDER_PATH in "${FOLDERS_TO_DESTROY[@]}"; do
        TFVARS_FILE=$(get_tfvars_file "$FOLDER_PATH")

        echo "### Destroying resources in: $FOLDER_PATH using $TFVARS_FILE ###"
        if [ -d "$FOLDER_PATH" ]; then
            cd "$FOLDER_PATH"
            if ! terraform destroy -auto-approve -var-file="$TFVARS_FILE"; then
                echo "ERROR: Failed to destroy resources in $FOLDER_PATH. Exiting"
                cd - > /dev/null
                exit 1
            fi
            cd - > /dev/null
        else
            echo "ERROR: Folder '$FOLDER_PATH' not found during destroy phase. Exiting."
            exit 1
        fi
        echo ""
    done

    echo "Terraform Infrastructure Destruction Complete"
    echo "Please verify that all resources have been removed."

else
    echo "Destruction cancelled by user. No resources were destroyed."
fi