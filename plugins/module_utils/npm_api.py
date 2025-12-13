import json
import os
import requests

# Default Config for CLI usage
CONFIG_FILE = 'nginx-proxy.json'

class NPMClient:
    def __init__(self, url=None, email=None, password=None):
        self.session = requests.Session()
        self.base_url = url
        self.email = email
        self.password = password
        self.token = None

        # If credentials weren't passed (CLI mode), try loading them
        if not all([self.base_url, self.email, self.password]):
            self._load_config()

        # Normalize URL
        if self.base_url:
            self.base_url = self.base_url.rstrip('/') + '/api'

        # Auto-login
        if self.base_url and self.email and self.password:
            self.authenticate()

    def _load_config(self):
        """Load from Env Vars or JSON file (CLI Helper)"""
        self.base_url = os.getenv('NPM_URL')
        self.email = os.getenv('NPM_EMAIL')
        self.password = os.getenv('NPM_PASSWORD')

        if not all([self.base_url, self.email, self.password]):
            if os.path.exists(CONFIG_FILE):
                try:
                    with open(CONFIG_FILE, 'r') as f:
                        config = json.load(f)
                        if not self.base_url: self.base_url = config.get('url')
                        if not self.email: self.email = config.get('email')
                        if not self.password: self.password = config.get('password')
                except Exception:
                    # In Ansible mode, we might not have stdout, so we pass
                    pass

    def authenticate(self):
        try:
            url = f"{self.base_url}/tokens"
            payload = {"identity": self.email, "secret": self.password}
            resp = self.session.post(url, json=payload)
            resp.raise_for_status()
            self.token = resp.json()['token']
            self.session.headers.update({"Authorization": f"Bearer {self.token}"})
        except Exception as e:
            raise Exception(f"Authentication failed for {self.email}: {str(e)}")

    def _req(self, method, endpoint, data=None):
        """Internal Helper for API Requests"""
        url = f"{self.base_url}/{endpoint}"
        try:
            resp = self.session.request(method, url, json=data)
            resp.raise_for_status()
            if resp.status_code == 204:
                return True
            return resp.json()
        except requests.exceptions.HTTPError as e:
            raise Exception(f"API {method} {endpoint} failed ({e.response.status_code}): {e.response.text}")

    # --- GENERIC LIST/DELETE/ENABLE ---
    def list_items(self, endpoint):
        return self._req('GET', endpoint)

    def delete_item(self, endpoint, item_id):
        return self._req('DELETE', f"{endpoint}/{item_id}")

    def toggle_enable(self, endpoint, item_id, action):
        return self._req('POST', f"{endpoint}/{item_id}/{action}")

    # --- PROXY HOSTS ---
    def get_proxy(self, domain):
        for i in self.list_items("nginx/proxy-hosts"):
            if domain in i.get('domain_names', []): return i
        return None

    def create_proxy(self, d): return self._req('POST', "nginx/proxy-hosts", d)
    def update_proxy(self, id, d): return self._req('PUT', f"nginx/proxy-hosts/{id}", d)

    # --- REDIRECTION HOSTS ---
    def get_redirect(self, domain):
        for i in self.list_items("nginx/redirection-hosts"):
            if domain in i.get('domain_names', []): return i
        return None

    def create_redirect(self, d): return self._req('POST', "nginx/redirection-hosts", d)
    def update_redirect(self, id, d): return self._req('PUT', f"nginx/redirection-hosts/{id}", d)

    # --- DEAD HOSTS (404) ---
    def get_dead(self, domain):
        for i in self.list_items("nginx/dead-hosts"):
            if domain in i.get('domain_names', []): return i
        return None

    def create_dead(self, d): return self._req('POST', "nginx/dead-hosts", d)
    def update_dead(self, id, d): return self._req('PUT', f"nginx/dead-hosts/{id}", d)

    # --- STREAMS ---
    def get_stream(self, in_port):
        for i in self.list_items("nginx/streams"):
            if int(i.get('incoming_port')) == int(in_port): return i
        return None

    def create_stream(self, d): return self._req('POST', "nginx/streams", d)
    def update_stream(self, id, d): return self._req('PUT', f"nginx/streams/{id}", d)

    # --- USERS ---
    def get_user(self, email):
        for i in self.list_items("users"):
            if i.get('email') == email: return i
        return None

    def create_user(self, d): return self._req('POST', "users", d)
    def update_user(self, id, d): return self._req('PUT', f"users/{id}", d)

    def update_user_auth(self, id, secret):
        return self._req('PUT', f"users/{id}/auth", {"type": "password", "secret": secret})

    # --- CERTIFICATES ---
    def get_cert(self, domain):
        # Fuzzy match: returns cert if the main domain is in the list
        for i in self.list_items("nginx/certificates"):
            if domain in i.get('domain_names', []): return i
        return None

    def create_cert(self, d): return self._req('POST', "nginx/certificates", d)

    # --- AUDIT (Export for comparison) ---
    def generate_audit_json(self):
        """
        Fetches all data, sanitizes it (removes IDs, dates, passwords),
        resolves relationships (ID -> Name), and returns a clean dictionary.
        """
        # Fetch data
        raw_users = self.list_items("users")
        raw_certs = self.list_items("nginx/certificates")
        raw_acls  = self.list_items("nginx/access-lists")
        raw_proxies = self.list_items("nginx/proxy-hosts")
        raw_redirects = self.list_items("nginx/redirection-hosts")
        raw_streams = self.list_items("nginx/streams")

        # Maps for resolution
        user_map = {u['id']: u['email'] for u in raw_users}
        cert_map = {c['id']: c.get('nice_name', 'Unknown') for c in raw_certs}
        acl_map  = {a['id']: a['name'] for a in raw_acls}

        # Cleaner helper
        def clean_obj(obj, keys_to_remove):
            for key in keys_to_remove:
                obj.pop(key, None)
            return obj

        base_ignore = [
            'id', 'created_on', 'modified_on', 'meta',
            'owner_user_id', 'certificate_id', 'access_list_id'
        ]

        # Clean Entities
        clean_users = []
        for u in raw_users:
            c = clean_obj(u.copy(), ['id', 'created_on', 'modified_on', 'is_disabled', 'avatar'])
            clean_users.append(c)

        clean_certs = []
        for c in raw_certs:
            cl = clean_obj(c.copy(), base_ignore + ['expires_on'])
            cl['owner'] = user_map.get(c.get('owner_user_id'))
            clean_certs.append(cl)

        clean_proxies = []
        for p in raw_proxies:
            cl = clean_obj(p.copy(), base_ignore)
            cl['owner'] = user_map.get(p.get('owner_user_id'))
            cl['certificate_name'] = cert_map.get(p.get('certificate_id'), "None")
            cl['access_list_name'] = acl_map.get(p.get('access_list_id'), "Public")
            clean_proxies.append(cl)

        clean_redirects = []
        for r in raw_redirects:
            cl = clean_obj(r.copy(), base_ignore)
            cl['owner'] = user_map.get(r.get('owner_user_id'))
            clean_redirects.append(cl)

        clean_streams = []
        for s in raw_streams:
            cl = clean_obj(s.copy(), base_ignore)
            cl['owner'] = user_map.get(s.get('owner_user_id'))
            clean_streams.append(cl)

        # Sort for consistent diffs
        clean_users.sort(key=lambda x: x['email'])
        clean_certs.sort(key=lambda x: x.get('nice_name', ''))
        clean_proxies.sort(key=lambda x: x.get('domain_names', [''])[0])
        clean_redirects.sort(key=lambda x: x.get('domain_names', [''])[0])
        clean_streams.sort(key=lambda x: x.get('incoming_port', 0))

        return {
            "summary": {
                "users": len(clean_users),
                "certs": len(clean_certs),
                "proxies": len(clean_proxies),
                "redirects": len(clean_redirects),
                "streams": len(clean_streams)
            },
            "users": clean_users,
            "certificates": clean_certs,
            "proxy_hosts": clean_proxies,
            "redirection_hosts": clean_redirects,
            "streams": clean_streams
        }
