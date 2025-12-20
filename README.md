# Nginx Proxy Manager CLI & Ansible Collection

**Warning:** this is *a lot of AI code*. It works - but I didn't audit every line!

This project provides an interface for the Nginx Proxy Manager API, allowing you to automate configuration without the web UI.

## Usage

This tool supports two modes:

1.  **CLI Tool:** A standalone Python script for terminal management. [CLI Docs](docs/cli.md)
2.  **Ansible Collection:** Modules to manage NPM infrastructure as code. [Ansible Docs](docs/ansible.md)

This tool **does not** support full backup/restore via API because the API redacts sensitive secrets (keys, tokens).

Use Ansible to create a new instance and `npm-cli audit` to test if the sites are equal.

## License
[MIT](LICENSE)
