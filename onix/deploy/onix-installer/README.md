# BECKN Onix GCP Installer

## Introduction

The **BECKN Onix GCP Installer** automates the provisioning of infrastructure and application deployment for your BECKN ecosystem. It simplifies setup by managing cloud resources and deploying necessary components.

---

## Prerequisites

**Important:** This installer is designed to run on **macOS or Linux** environments and requires **Bash version 4.0 or higher**.

Follow these steps to prepare your environment before running the installer.

### Google Cloud Project
You must have google cloud project with 
 - Billing enabled.
 - The following APIs enabled:
    -  Compute Engine API
    -  Kubernetes Engine API
    -  Cloud Resource Manager API
    -  Service Networking API
    -  Secret Manager API
    -  Google Cloud Memorystore for Redis API
    -  Cloud SQL Admin API
    -  Artifact Registry API

### Registered Domain Names
You will need at least one registered domain name (e.g., your-company.com) for which you have administrative access.

Why? These domains are required to expose the Onix services (like the gateway, registry, adapter or subscriber) to the public internet securely.

### Required Tools
   
-   **Google Cloud SDK (`gcloud`)**: For authenticating with Google Cloud and managing resources.
    -   Follow the [official installation guide](https://cloud.google.com/sdk/docs/install).
    -   After installation, run `gcloud init` and `gcloud auth login`.
-   **Terraform**: For provisioning infrastructure as code.
    -   [Installation Guide](https://learn.hashicorp.com/tutorials/terraform/install-cli)
-   **Helm**: For deploying applications onto Kubernetes.
    -   [Installation Guide](https://helm.sh/docs/intro/install/)
-   **kubectl**: A command-line tool for interacting with Kubernetes.
    -   [Installation Guide](https://kubernetes.io/docs/tasks/tools/install-kubectl/)
-   **Docker**: For building and running containers.
    -   [Installation Guide](https://docs.docker.com/engine/install/)
-   **Additional Tools**:
    -   **gsutil**: [Installation Guide](https://cloud.google.com/storage/docs/gsutil_install)
    -   **jq**: [Installation Guide](https://jqlang.github.io/jq/download/)
    -   **gke-gcloud-auth-plugin**: [Installation Guide](https://cloud.google.com/kubernetes-engine/docs/how-to/cluster-access-for-kubectl#install_plugin)
    -   **psql**: [Installation Guide](https://www.postgresql.org/download/)
-   **Python 3.12**:
    For Linux:
    ```bash
    sudo add-apt-repository ppa:deadsnakes/ppa
    sudo apt update
    sudo apt install python3.12 python3.12-venv
    ```
    For Mac:
     ```bash
    brew install pyenv
    pyenv install 3.12.0
    pyenv global 3.12.0
    ```

-   **Go**:
    [Installation Guide] https://go.dev/doc/install

    **Node.js & Angular**:
    ```bash
    # Install Node.js (LTS) via nvm
    curl -o nvm_install.sh https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh
    chmod 700 nvm_install.sh
    ./nvm_install.sh
    export NVM_DIR="$HOME/.nvm"
    [ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"
    nvm install --lts

    # Install Angular CLI
    npm install -g @angular/cli
    ```

---

## Installation and Setup

### 1. Set Up IAM Permissions for Your User

Ensure the user account running the installer has the following IAM roles on the GCP project. **Note**: These are required even if the user has the "Owner" role.

-   Service Account Token Creator
-   Service Account User
-   Service Account Admin
-   Project IAM Admin (or IAM Role Admin & IAM Policy Admin)
-   Secret Manager Admin
-   Cloud SQL Admin
-   Artifact Registry Administrator
-   Artifact Registry Administrator
-   Kubernetes Engine Cluster Admin
-   Storage Object Admin


### 2. Create and Configure the Installer Service Account

The installer requires a dedicated service account to manage resources.

**Option A: Automated Script (Recommended)**

The provided `installer.sh` script can create the service account and assign all required roles automatically. It will prompt for your Project ID and a service account name.

**Option B: Manual Setup**

If you prefer, create a service account in the GCP Console and manually assign it the following roles:

-   Cloud Memorystore Redis Admin
-   Cloud SQL Admin
-   Cloud Trace Agent
-   Compute Instance Admin (v1)
-   Compute Network Admin
-   Kubernetes Engine Cluster Admin
-   Project IAM Admin
-   Pub/Sub Admin & Publisher
-   Secret Manager Admin & Accessor
-   Security Admin
-   Service Account Admin & Token Creator
-   Storage Admin & Object Admin
-   Compute Security Admin
-   Compute Load Balancer Admin
-   Kubernetes Engine Admin
-   Logging Admin
-   Monitoring Admin
-   Service Account User
-   DNS Administrator


### 3. Configuration

Set your active GCP project in the `gcloud` CLI:

```bash
gcloud config set project your-project-id
```


### 4. Verify Tool Installation
gcloud --version
terraform --version
helm version
kubectl version --client
docker --version
gsutil version
jq --version
gke-gcloud-auth-plugin --version
python3 --version
go version

### 5. Create Build Artifacts

Before running the installer, you need to build and push the required Docker images to your Artifact Registry.
**Note** Make sure Docker daemon is running in your system

**A. Set Up Google Artifact Registry**

1.  Choose a location (e.g., `asia-south1`) and a name for your repository (e.g., `onix-artifacts`).

2.  Create the Docker repository:
    ```bash
    gcloud artifacts repositories create onix-artifacts \
        --repository-format=docker \
        --location=asia-south1 \
        --description="BECKN Onix Docker repository"
    ```

3.  Configure Docker to authenticate with Artifact Registry:
    ```bash
    gcloud auth configure-docker asia-south1-docker.pkg.dev
    ```

**B. Build and Push the Adapter Image**

1.  Set environment variables for your GCP project, location, and repository name:
    ```bash
    export GCP_PROJECT_ID=$(gcloud config get-value project)
    export AR_LOCATION=asia-south1
    export AR_REPO_NAME=onix-artifacts
    export REGISTRY_URL=${AR_LOCATION}-docker.pkg.dev/${GCP_PROJECT_ID}/${AR_REPO_NAME}
    ```

2.  Update the `source.yaml` file with your registry URL. The file is located at `onix/deploy/onix-installer/adapter_artifacts/source.yaml`. Uncomment the `registry` field and replace the placeholder `<REGISTRY_URL>` with the value of `$REGISTRY_URL`.

3.  Build and run `onixctl` to build the adapter image and plugins:
    ```bash
    cd onix && go build ./cmd/onixctl && cd ..
    ./onix/onixctl --config onix/deploy/onix-installer/adapter_artifacts/source.yaml
    ```

**C. Build and Push Core Service Images**

Build and push the Docker images for the gateway, registry, registry-admin, and subscriber services.

```bash
export TAG=latest # Or any tag you prefer

# Gateway
docker buildx build --platform linux/amd64 -t $REGISTRY_URL/gateway:$TAG -f onix/Dockerfile.gateway onix
docker push $REGISTRY_URL/gateway:$TAG

# Registry
docker buildx build --platform linux/amd64 -t $REGISTRY_URL/registry:$TAG -f onix/Dockerfile.registry onix
docker push $REGISTRY_URL/registry:$TAG

# Registry Admin
docker buildx build --platform linux/amd64 -t $REGISTRY_URL/registry-admin:$TAG -f onix/Dockerfile.registry-admin onix
docker push $REGISTRY_URL/registry-admin:$TAG

# Subscriber
docker buildx build --platform linux/amd64 -t $REGISTRY_URL/subscriber:$TAG -f onix/Dockerfile.subscriber onix
docker push $REGISTRY_URL/subscriber:$TAG
```

### 5. Run the installer
Once all prerequisites and configurations are complete, change into the installer directory and execute the installer script:

```bash
 cd onix/deploy/onix-installer
 make run-installer
```
Note it will run both backend and fronted of installer application and you can find logs on logs folder

### 6. Access installer UI
go to any browser, and open localhost:4200

### 7. Prepare Adapter Deployment Artifacts

Before proceeding with the application deployment step in the installer, if either a BAP (Buyer Application Provider) or BPP (Seller Application Provider) is being deployed, ensure that the `adapter_artifacts` folder contains the necessary artifacts.

-   **`schemas` folder**: This folder is needed if you want to enable schema validation. It should contain all required schema files.
-   **`routing_configs` folder**: This folder must contain the routing configuration files specific to your deployment:
    -   `bapTxnReceiver-routing.yaml`: Required if a BAP is being deployed.
    -   `bapTxnCaller-routing.yaml`: Required if a BAP is being deployed.
    -   `bppTxnReceiver-routing.yaml`: Required if a BPP is being deployed.
    -   `bppTxnCaller-routing.yaml`: Required if a BPP is being deployed.
-   **`plugins` folder**: This folder should contain the plugin bundle, which is a `.zip` file.

***Important Notes***
- Please add your routing config .yaml files in adapter_artifacts/routing_configs folder before infra deployment step.
- If you are using pubsub please add Adapter topic name from infra deployment output and add in .yaml files in adapter_artifacts/routing_configs folder.


---

## Cleanup and Destruction
To uninstall Onix and delete all associated infrastructure, run the following command from the onix/deploy/onix-installer directory.

 ⚠️ Warning: This command is irreversible. It will delete all infrastructure created by the installer (such as GKE clusters, databases, and Redis instances) and will also delete all Onix services that you created through the installer

```bash 
 make destroy-infra
```
   