import requests


class NPMClient:
    def __init__(self, url=None, email=None, password=None):
        self.session = requests.Session()
        self.base_url = url
        self.email = email
        self.password = password
        self.token = None

        # Normalize URL
        if self.base_url:
            self.base_url = self.base_url.rstrip("/") + "/api"

        # Auto-login if we have creds
        if self.base_url and self.email and self.password:
            self.authenticate()

    def authenticate(self):
        try:
            url = f"{self.base_url}/tokens"
            payload = {"identity": self.email, "secret": self.password}
            resp = self.session.post(url, json=payload)
            resp.raise_for_status()
            self.token = resp.json()["token"]
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
            if "application/json" in resp.headers.get("Content-Type", ""):
                return resp.json()
            return resp.content
        except requests.exceptions.HTTPError as e:
            raise Exception(f"API {method} {endpoint} failed ({e.response.status_code}): {e.response.text}")

    # --- GENERIC LIST/DELETE/ENABLE ---

    def list_items(self, endpoint):
        return self._req("GET", endpoint)

    def delete_item(self, endpoint, item_id):
        return self._req("DELETE", f"{endpoint}/{item_id}")

    def toggle_enable(self, endpoint, item_id, action):
        return self._req("POST", f"{endpoint}/{item_id}/{action}")

    # --- ACCESS LISTS ---
    def list_access_lists(self):
        return self._req("GET", "nginx/access-lists")

    def get_access_list(self, id):
        return self._req("GET", f"nginx/access-lists/{id}")

    def create_access_list(self, d):
        return self._req("POST", "nginx/access-lists", d)

    def update_access_list(self, id, d):
        return self._req("PUT", f"nginx/access-lists/{id}", d)

    def delete_access_list(self, id):
        return self._req("DELETE", f"nginx/access-lists/{id}")

    # --- CERTIFICATES ---
    def get_cert(self, domain):
        for i in self.list_items("nginx/certificates"):
            if domain in i.get("domain_names", []):
                return i
        return None

    def create_cert(self, d):
        return self._req("POST", "nginx/certificates", d)

    def list_dns_providers(self):
        return self._req("GET", "nginx/certificates/dns-providers")

    def validate_certificate(self, d):
        return self._req("POST", "nginx/certificates/validate", d)

    def test_http_challenge(self, d):
        return self._req("POST", "nginx/certificates/test-http", d)

    def download_certificate(self, id):
        return self._req("GET", f"nginx/certificates/{id}/download")

    def renew_certificate(self, id):
        return self._req("POST", f"nginx/certificates/{id}/renew")

    def upload_certificate(self, d):
        return self._req("POST", "nginx/certificates/upload", d)

    def delete_certificate(self, id):
        return self._req("DELETE", f"nginx/certificates/{id}")

    # --- DEAD HOSTS (404) ---
    def get_dead(self, domain):
        for i in self.list_items("nginx/dead-hosts"):
            if domain in i.get("domain_names", []):
                return i
        return None

    def create_dead(self, d):
        return self._req("POST", "nginx/dead-hosts", d)

    def update_dead(self, id, d):
        return self._req("PUT", f"nginx/dead-hosts/{id}", d)

    def enable_dead_host(self, id):
        return self._req("POST", f"nginx/dead-hosts/{id}/enable")

    def disable_dead_host(self, id):
        return self._req("POST", f"nginx/dead-hosts/{id}/disable")

    # --- PROXY HOSTS ---
    def get_proxy(self, domain):
        for i in self.list_items("nginx/proxy-hosts"):
            if domain in i.get("domain_names", []):
                return i
        return None

    def create_proxy(self, d):
        return self._req("POST", "nginx/proxy-hosts", d)

    def update_proxy(self, id, d):
        return self._req("PUT", f"nginx/proxy-hosts/{id}", d)

    def enable_proxy_host(self, id):
        return self._req("POST", f"nginx/proxy-hosts/{id}/enable")

    def disable_proxy_host(self, id):
        return self._req("POST", f"nginx/proxy-hosts/{id}/disable")

    # --- REDIRECTION HOSTS ---
    def get_redirect(self, domain):
        for i in self.list_items("nginx/redirection-hosts"):
            if domain in i.get("domain_names", []):
                return i
        return None

    def create_redirect(self, d):
        return self._req("POST", "nginx/redirection-hosts", d)

    def update_redirect(self, id, d):
        return self._req("PUT", f"nginx/redirection-hosts/{id}", d)

    def enable_redirect_host(self, id):
        return self._req("POST", f"nginx/redirection-hosts/{id}/enable")

    def disable_redirect_host(self, id):
        return self._req("POST", f"nginx/redirection-hosts/{id}/disable")

    # --- REPORTS ---
    def get_hosts_report(self):
        return self._req("GET", "reports/hosts")

    # --- SETTINGS ---
    def list_settings(self):
        return self._req("GET", "settings")

    def get_setting(self, id):
        return self._req("GET", f"settings/{id}")

    def update_setting(self, id, d):
        return self._req("PUT", f"settings/{id}", d)

    # --- STREAMS ---
    def get_stream(self, in_port):
        for i in self.list_items("nginx/streams"):
            if int(i.get("incoming_port")) == int(in_port):
                return i
        return None

    def create_stream(self, d):
        return self._req("POST", "nginx/streams", d)

    def update_stream(self, id, d):
        return self._req("PUT", f"nginx/streams/{id}", d)

    def enable_stream(self, id):
        return self._req("POST", f"nginx/streams/{id}/enable")

    def disable_stream(self, id):
        return self._req("POST", f"nginx/streams/{id}/disable")

    # --- USERS ---
    def get_user(self, email):
        for i in self.list_items("users"):
            if i.get("email") == email:
                return i
        return None

    def create_user(self, d):
        return self._req("POST", "users", d)

    def update_user(self, id, d):
        return self._req("PUT", f"users/{id}", d)

    def update_user_auth(self, id, secret):
        return self._req("PUT", f"users/{id}/auth", {"type": "password", "secret": secret})

    def get_user_by_id(self, id):
        return self._req("GET", f"users/{id}")

    def delete_user(self, id):
        return self._req("DELETE", f"users/{id}")

    def update_user_permissions(self, id, d):
        return self._req("PUT", f"users/{id}/permissions", d)

    # --- GENERAL ---
    def version_check(self):
        return self._req("GET", "version/check")

    def get_schema(self):
        return self._req("GET", "schema")
