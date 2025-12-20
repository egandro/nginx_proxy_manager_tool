# Ansible Collection Usage

This repository allows you to manage Nginx Proxy Manager resources using standard Ansible tasks.

## Installation

Since this collection is hosted on GitHub, install it using `ansible-galaxy` with the git URL:

```bash
ansible-galaxy collection install git+https://github.com/egandro/nginx_proxy_manager_tool.git
```

## Requirements

The target machine (where the modules execute, usually `localhost`) must have the Python dependencies installed:

```bash
pip install requests
```

## Available Modules

*   `npm_proxy`: Manage Proxy Hosts
*   `npm_redirect`: Manage Redirection Hosts
*   `npm_dead_host`: Manage 404 Hosts
*   `npm_stream`: Manage TCP/UDP Streams
*   `npm_cert`: Manage Certificates (LetsEncrypt)
*   `npm_user`: Manage Users
*   `npm_acl`: Manage Access Lists
*   `npm_setting`: Manage Global Settings

## Module Parameters

### Common Parameters
All modules accept the following connection and state parameters:
*   `url`: (Required) The base URL of your NPM instance (e.g., `http://npm.local:81`).
*   `email`: (Required) Admin email address for authentication.
*   `password`: (Required) Admin password.
*   `state`: Target state. `present` (create/update) or `absent` (delete). Default: `present`.

### npm_proxy
*   `domain`: (Required) The incoming domain name (e.g., `app.example.com`).
*   `forward_host`: (Required) The target internal IP or hostname.
*   `forward_port`: (Required) The target internal port.
*   `forward_scheme`: The protocol to talk to the target. `http` or `https`. Default: `http`.
*   `websockets`: (Boolean) Enable Websocket support. Default: `false`.
*   `ssl_forced`: (Boolean) Force HTTPS. Default: `false`.
*   `http2`: (Boolean) Enable HTTP/2 support. Default: `false`.
*   `hsts_enabled`: (Boolean) Enable HSTS. Default: `false`.
*   `hsts_subdomains`: (Boolean) Enable HSTS Subdomains. Default: `false`.
*   `block_exploits`: (Boolean) Block common exploits. Default: `false`.
*   `caching`: (Boolean) Enable caching. Default: `false`.
*   `certificate_id`: Existing Certificate Id. Default: `0`.
*   `access_list_id`: Existing Access List Id. Default: `0`.
*   `advanced_config`: Advanced Config. Default: ``.
*   `enabled`: (Boolean) Enable the host. Default: `true`.

### npm_redirect
*   `domain`: (Required) The incoming domain name.
*   `forward_domain`: The destination URL (e.g., `https://google.com`).
*   `forward_http_code`: HTTP Status Code (300, 301, 302, 307, 308). Default: `301`.
*   `forward_scheme`: The protocol (`http`, `https`, `auto`). Default: `auto`.
*   `preserve_path`: (Boolean) If true, appends the path to the destination URL.
*   `block_exploits`: (Boolean) Block common exploits. Default: `false`.
*   `ssl_forced`: (Boolean) Force HTTPS. Default: `false`.
*   `certificate_id`: Existing Certificate Id. Default: `0`.
*   `advanced_config`: Advanced Config. Default: ``.
*   `enabled`: (Boolean) Enable the host. Default: `true`.

### npm_dead_host
*   `domain`: (Required) The domain that should return a 404 Not Found error.
*   `certificate_id`: Existing Certificate Id. Default: `0`.
*   `ssl_forced`: (Boolean) Force HTTPS. Default: `false`.
*   `enabled`: (Boolean) Enable the host. Default: `true`.

### npm_stream
*   `incoming_port`: (Required) The port Nginx will listen on.
*   `forward_host`: The target internal IP or hostname.
*   `forward_port`: The target internal port.
*   `tcp`: (Boolean) Enable TCP forwarding. Default: `true`.
*   `udp`: (Boolean) Enable UDP forwarding. Default: `false`.
*   `enabled`: (Boolean) Enable the stream. Default: `true`.

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
*   `target_nickname`: The nickname of the user.
*   `target_password`: The user's password. It will only update the password if this parameter is present.
*   `is_admin`: (Boolean) Grant system administrator permissions. Default: `false`.
*   `is_disabled`: (Boolean) Disable the user. Default: `false`.
*   `permissions`: (Dict) Granular permissions object.

### npm_acl
*   `name`: (Required) Name of the Access List.
*   `satisfy_any`: (Boolean) Satisfy any condition. Default: `false`.
*   `users`: (List) List of users (dicts with `username` and `password`).

### npm_setting
*   `name`: (Required) The setting ID (e.g., `default-site`).
*   `value`: (Required) The value to set. Valid options are: `congratulations`, `404`, `444`, `redirect`, `html`.
*   `meta_redirect`: (String) Redirect URL. Required if value is `redirect`.
*   `meta_html`: (String) HTML Content. Required if value is `html`.

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
    - name: Ensure Certificate exists
      npm_cert:
        url: "{{ npm_url }}"
        email: "{{ npm_user }}"
        password: "{{ npm_pass }}"
        state: present
        domain: "*.internal.io" # can be wildcard with a provider
        le_email: "admin@example.com"
        provider: "cloudflare" # You can use duckdns with a free domain for testing
        # You can pass the API token directly or read from a file lookup
        dns_credentials: "dns_cloudflare_api_token = 123456789"
      register: result

    - name: Ensure Proxy Host exists
      npm_proxy:
        url: "{{ npm_url }}"
        email: "{{ npm_user }}"
        password: "{{ npm_pass }}"
        state: present
        domain: "app.internal.io"
        # forward_scheme: https (http is default)
        forward_host: "10.10.10.50"
        forward_port: 8080
        # ssl_forced: true
        # certificate_id: "{{ result.id }}"
        # websockets: true
        # http2: true
        # hsts_subdomains: true
        # hsts_enabled: true
        # block_exploits: true
        # caching: true
        # advanced_config: |
        #   // foo
        #   // bar

    - name: Ensure Redirect exists
      npm_redirect:
        url: "{{ npm_url }}"
        email: "{{ npm_user }}"
        password: "{{ npm_pass }}"
        state: present
        domain: "old-site.com"
        forward_domain: "https://new-site.com"
        forward_http_code: 301

    - name: Create Access List
      npm_acl:
        url: "{{ npm_url }}"
        email: "{{ npm_user }}"
        password: "{{ npm_pass }}"
        state: present
        name: "Internal Team"
        users:
          - username: "dev"
            password: "secure_password"

    - name: Set Default Site
      npm_setting:
        url: "{{ npm_url }}"
        email: "{{ npm_user }}"
        password: "{{ npm_pass }}"
        name: "default-site"
        value: "congratulations"
```
