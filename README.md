# Nginx Proxy Manager CLI & Ansible Collection

**Warning:** this is *a lot of AI code*. It works - but I didn't audit every line!

This project provides a robust interface for the [Nginx Proxy Manager](https://nginxproxymanager.com/) API. It solves the problem of automating host creation, certificate requests, and user management without using the web UI.

## 🚀 Dual Mode Usage

This repository is designed to be used in two distinct ways, depending on your workflow:

### Mode 1: The CLI Tool
A standalone Python script for admins who want to manage NPM from the terminal.
*   **Best for:** Quick edits, scripting, auditing, and comparing configurations between servers.
*   **Installation:** Simply clone this repo and run the script.
*   [📖 Read the CLI Documentation](docs/cli_usage.md)

### Mode 2: Ansible Collection
A full-featured Ansible Collection to manage NPM infrastructure as code.
*   **Best for:** Idempotent deployments, GitOps, and configuration management.
*   **Installation:** Install directly from GitHub using `ansible-galaxy`.
*   [📖 Read the Ansible Documentation](docs/ansible_usage.md)

## 📋 Supported Features

Both the CLI and Ansible modules support the following features:

*   **Proxy Hosts:** Create, update, delete, enable/disable.
*   **Redirections:** Manage 301/302 redirects.
*   **Dead Hosts:** Manage 404 responses.
*   **Streams:** Manage TCP/UDP streams.
*   **Certificates:** Request Let's Encrypt certificates (HTTP & DNS/Wildcard challenges).
*   **Users:** Create and manage admin users.
*   **Auditing (CLI Only):** Export sanitized JSON for config comparison.

## ⚠️ A Note on Backup & Restore

You might notice this tool **does not** include a full "Restore" function. This is intentional.

**Why the API is bad for backups:**
1.  **ID Mapping:** Restoring via API requires mapping old Database IDs to new Database IDs for every dependency (Users → Access Lists → Certs → Hosts). This is fragile and error-prone.
2.  **Missing Secrets:** For security reasons, the API **redacts** sensitive data (like Certificate Private Keys and DNS API secrets). An API-based backup would be incomplete.

**The Recommended Solution:**
To backup or migrate your Nginx Proxy Manager instance effectively, simply backup the filesystem:
1.  Stop the container.
2.  Copy the `data` (SQLite/MySQL database) and `letsencrypt` folders.
3.  Paste them into the new instance.
4.  Start the container.

## 📄 License
[MIT](LICENSE)
