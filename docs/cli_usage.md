# CLI Tool Usage

## ⚙️ Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/your_username/npm-automation.git
    cd npm-automation
    ```
2.  **Install Dependencies:**
    ```bash
    pip install -r requirements.txt
    ```
    *(Requires `requests` and `tabulate`)*

## 🔧 Configuration

You can configure authentication using either Environment Variables (recommended for CI/CD) or a local JSON file.

**Option 1: Environment Variables**
```bash
export NPM_URL="http://npm.example.com"
export NPM_EMAIL="admin@example.com"
export NPM_PASSWORD="secure_password"
```

**Option 2: Config File**
Create a file named `nginx-proxy.json` in the script directory:
```json
{
  "url": "http://npm.example.com",
  "email": "admin@example.com",
  "password": "secure_password"
}
```

## 🚀 Basic Usage

```bash
./npm_cli.py [category] [action] [arguments]
```

**Global Options:**
*   `--json`: Output the result as raw JSON instead of a formatted table.

**Categories:**
`proxy`, `redirect`, `404`, `stream`, `cert`, `user`, `audit`, `acl`, `setting`, `report`, `system`

## 💡 Examples

### 1. Proxy Host Management

**List and Search**
```bash
# List all hosts
./npm_cli.py proxy list

# Search for a specific host (by domain or IP)
./npm_cli.py proxy search "blog"
```

**Create a Secure Proxy**
Forward `secure.example.com` to an internal IP with forced SSL, HTTP/2, and Websockets enabled:
```bash
./npm_cli.py proxy create \
  --domains secure.example.com \
  --ip 192.168.1.50 \
  --port 8080 \
  --ssl-forced \
  --http2 \
  --websockets
```

### 2. Certificate Management

**List DNS Providers**
View supported providers and the required credential format:
```bash
./npm_cli.py cert providers
```

**Create a Wildcard Cert (DNS Challenge)**
Using a credential file is recommended for security. Create `cloudflare.ini` with your API token inside.
```bash
./npm_cli.py cert create-dns \
  --domains "*.example.com" "example.com" \
  --email admin@example.com \
  --provider cloudflare \
  --credentials ./cloudflare.ini \
  --propagation 120
```

### 3. Auditing & Comparison

The `audit` command exports your entire configuration (Hosts, Users, Certs) into a single JSON object. It sanitizes the data (removes IDs, dates, and passwords) and sorts it.

**Use Case:** Verify if your old server matches a new server.

```bash
# Export config from Server Old
./npm_cli.py audit > backup_config.json

# Export config from Server New
./npm_cli.py audit > new_config.json

# Compare them
diff backup_config.json new_config.json
```
