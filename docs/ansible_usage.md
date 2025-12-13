# Ansible Collection Usage

This repository allows you to manage Nginx Proxy Manager resources using standard Ansible tasks. The modules use the API to ensure idempotency (they check if a resource exists before creating or updating it).

## ⚙️ Installation

Since this collection is hosted on GitHub, install it using `ansible-galaxy` with the git URL:

```bash
ansible-galaxy collection install git+https://github.com/egandro/nginx_proxy_manager_tool.git
```

## 🔧 Requirements

The target machine (where the modules execute, usually `localhost`) must have the Python dependencies installed:

```bash
pip install requests
```

## 📦 Available Modules

*   `npm_proxy`: Manage Proxy Hosts
*   `npm_redirect`: Manage Redirection Hosts
*   `npm_dead_host`: Manage 404 Hosts
*   `npm_stream`: Manage TCP/UDP Streams
*   `npm_cert`: Manage Certificates (LetsEncrypt)
*   `npm_user`: Manage Users

## 📝 Module Parameters

### Common Parameters
All modules accept the following connection and state parameters:
*   `url`: (Required) The base URL of your NPM instance (e.g., `http://npm.local:81`).
*   `email`: (Required) Admin email address for authentication.
*   `password`: (Required) Admin password.
*   `state`: Target state. `present` (create/update) or `absent` (delete). Default: `present`.

### npm_proxy
*   `domain`: (Required) The incoming domain name (e.g., `app.example.com`).
*   `forward_host`: The target internal IP or hostname.
*   `forward_port`: The target internal port.
*   `ssl_forced`: (Boolean) If true, forces HTTPS redirection.

### npm_redirect
*   `domain`: (Required) The incoming domain name.
*   `forward_domain`: The destination URL (e.g., `https://google.com`).
*   `forward_http_code`: HTTP Status Code (300, 301, 302, 307, 308). Default: `301`.
*   `preserve_path`: (Boolean) If true, appends the path to the destination URL.

### npm_dead_host
*   `domain`: (Required) The domain that should return a 404 Not Found error.

### npm_stream
*   `incoming_port`: (Required) The port Nginx will listen on.
*   `forward_host`: The target internal IP or hostname.
*   `forward_port`: The target internal port.
*   `tcp`: (Boolean) Enable TCP forwarding. Default: `true`.
*   `udp`: (Boolean) Enable UDP forwarding. Default: `false`.

### npm_cert
*   `domain`: (Required) The primary domain name (CN).
*   `extra_domains`: (List) Additional domains (SANs).
*   `le_email`: (Required) Email address to register with Let's Encrypt.
*   `provider`: DNS Provider code (e.g., `cloudflare`, `route53`). Default: `letsencrypt` (standard HTTP challenge).
*   `dns_credentials`: Raw string (key=value) or file path to DNS API credentials. Required if provider is not `letsencrypt`.
*   `propagation`: (Integer) Seconds to wait for DNS propagation. Default: `120`.

### npm_user
*   `target_email`: (Required) The email address of the user to manage.
*   `target_name`: The display name of the user.
*   `target_password`: The user's password. It will only update the password if this parameter is present.
*   `is_admin`: (Boolean) Grant system administrator permissions. Default: `false`.

## 💡 Playbook Example

Here is a full example of how to configure a Proxy Host and a Redirect Host.

```yaml
---
- hosts: localhost
  connection: local
  gather_facts: false
  vars:
    npm_url: "http://npm.local:81"
    npm_user: "admin@example.com"
    npm_pass: "changeme"

  collections:
    - egandro.nginx_proxy_manager_tool

  tasks:
    - name: Ensure Proxy Host exists
      npm_proxy:
        url: "{{ npm_url }}"
        email: "{{ npm_user }}"
        password: "{{ npm_pass }}"
        state: present
        domain: "app.internal.io"
        forward_host: "10.10.10.50"
        forward_port: 8080
        ssl_forced: true
        # websocket_support: true

    - name: Ensure Redirect exists
      npm_redirect:
        url: "{{ npm_url }}"
        email: "{{ npm_user }}"
        password: "{{ npm_pass }}"
        state: present
        domain: "old-site.com"
        forward_domain: "https://new-site.com"
        forward_http_code: 301

    - name: Request Wildcard Certificate
      npm_cert:
        url: "{{ npm_url }}"
        email: "{{ npm_user }}"
        password: "{{ npm_pass }}"
        state: present
        domain: "*.internal.io"
        le_email: "admin@example.com"
        provider: "cloudflare"
        # You can pass the API token directly or read from a file lookup
        dns_credentials: "dns_cloudflare_api_token = 123456789"
```