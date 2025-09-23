# DPI Accelerator

This suite of open-source software accelerates the adoption of Digital Public Infrastructure (DPI). It provides a "DPI-as-a-Service" (DaaS) model with pre-packaged, cloud-ready components that allow nations to rapidly launch DPI pilots and bypass lengthy and costly traditional procurement and build cycles. The suite includes products like the Beckn Onix open network accelerator (GA) and ADK-based conversational agents (in private preview). Each deployment is an application layer innovation built on GCP stack, driving consumption of core infrastructure, data services, and advanced AI capabilities.

The primary project in this repository is **Onix**, an accelerator for building and deploying [Beckn](https://becknprotocol.io/)-compliant networks on Google Cloud.

## Onix: A Beckn Network Accelerator

Onix is a complete solution for deploying a Beckn network on Google Cloud. 
Beckn is an open protocol that enables location-aware, local commerce across industries. It allows consumers and providers to discover each other and engage in transactions on a decentralized network. This project implements the core components needed to create such a network. For a deeper dive into the reference implementation, visit the [official beckn-onix repository](https://github.com/Beckn-One/beckn-onix/).

It consists following:

1.  **Core Beckn Services**: A set of microservices written in Go that form the backbone of the network (Registry, Gateway, Adapters).
2.  **UI-Based Installer**: A web-based application that automates the entire deployment process, from provisioning GCP infrastructure with Terraform to deploying the core services with Helm.
3.  **Plugins**: These are GCP based pluggable modules for beckn-onix to have extensible and configurable functionalities in beckn-environment.

### Key Features

-   **Automated Deployment**: A simple, UI-driven workflow to get a full Beckn network running in minutes.
-   **Extensible Architecture**: A plugin-based system for adapters allows for custom logic and integrations.
-   **Cloud Native**: Designed to run on Google Cloud, leveraging services like GKE, Cloud SQL, and Pub/Sub.


For a more detailed technical overview of the Onix components, see the **[Onix Project README](./onix/README.md)**.

## Getting Started

The recommended way to deploy Onix is through the UI-based installer. For detailed prerequisites and instructions, please refer to the **[Onix Installer README](./onix/deploy/onix-installer/README.md)**.

## Repository Structure

-   `onix/`: Contains the core Onix project.
    -   `cmd/`: Main applications for each microservice.
    -   `deploy/onix-installer/`: The UI-based installer (Angular frontend, FastAPI backend).
    -   `internal/`: Shared business logic for the Onix services.
    -   `plugins/`: Source code for the extensible plugins used by the adapters.
    -   `configs/`: Detailed example configuration files for each service.
    -   `onixctl/`: A command-line tool for building adapter/plugin artifacts.

## Licensing

This project is licensed under the Apache 2.0 License. See the [LICENSE](./LICENSE) file for details.
