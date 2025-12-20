#!/usr/bin/env python3
import argparse
import json
import os
import sys
from tabulate import tabulate

# --- HYBRID REPO IMPORT SETUP ---
current_dir = os.path.dirname(os.path.abspath(__file__))
module_utils_path = os.path.join(current_dir, 'plugins', 'module_utils')
if os.path.exists(module_utils_path): sys.path.insert(0, module_utils_path)

try:
    from npm_api import NPMClient
    from npm_audit import generate_audit_json
except ImportError:
    print("CRITICAL ERROR: Could not import 'NPMClient' or 'npm_audit'.")
    sys.exit(1)

def output_result(data, headers, json_mode=False):
    if json_mode:
        print(json.dumps(data, indent=2, sort_keys=True))
    elif not data:
        print("No results found.")
    else:
        rows = [[item.get(h) for h in headers] for item in data]
        print(tabulate(rows, headers=headers, tablefmt="grid"))

def filter_data(data, query, search_keys):
    if not query: return data
    query = query.lower()
    filtered = []
    for item in data:
        match = False
        for key in search_keys:
            val = item.get(key)
            if isinstance(val, list):
                if any(query in str(x).lower() for x in val): match = True
            elif val and query in str(val).lower(): match = True
        if match: filtered.append(item)
    return filtered

def main():
    parser = argparse.ArgumentParser(description="Nginx Proxy Manager CLI")
    parser.add_argument("--json", action="store_true", help="Output JSON")
    subparsers = parser.add_subparsers(dest="category", help="Category")

    # AUDIT
    subparsers.add_parser("audit", help="Export sanitized config")

    # ACL
    acl = subparsers.add_parser("acl", help="Manage Access Lists")
    acl_sub = acl.add_subparsers(dest="action", required=True)
    acl_sub.add_parser("list")
    acl_create = acl_sub.add_parser("create")
    acl_create.add_argument("--name", required=True)
    acl_create.add_argument("--username", help="Basic Auth Username")
    acl_create.add_argument("--password", help="Basic Auth Password")
    acl_create.add_argument("--satisfy-any", action="store_true")
    acl_del = acl_sub.add_parser("delete"); acl_del.add_argument("id", type=int)
    acl_up = acl_sub.add_parser("update")
    acl_up.add_argument("id", type=int)
    acl_up.add_argument("--name")
    acl_up.add_argument("--satisfy-any", dest="satisfy_any", action="store_true", default=None)
    acl_up.add_argument("--items", help="JSON string of items")
    acl_up.add_argument("--username", help="Add or update a Basic Auth Username")
    acl_up.add_argument("--password", help="Password for the user")

    # PROXY
    p = subparsers.add_parser("proxy", help="Manage Proxy Hosts")
    p_sub = p.add_subparsers(dest="action", required=True)
    p_sub.add_parser("list")
    p_search = p_sub.add_parser("search")
    p_search.add_argument("query")
    p_create = p_sub.add_parser("create")
    p_create.add_argument("--domains", nargs='+', required=True)
    p_create.add_argument("--ip", required=True)
    p_create.add_argument("--port", type=int, required=True)
    p_create.add_argument("--scheme", choices=['http', 'https'], default='http')
    p_create.add_argument("--ssl-forced", action="store_true")
    p_create.add_argument("--caching", action="store_true")
    p_create.add_argument("--block-exploits", action="store_true")
    p_create.add_argument("--websockets", action="store_true")
    p_create.add_argument("--http2", action="store_true")
    p_create.add_argument("--hsts", action="store_true")
    p_create.add_argument("--pass-auth", action="store_true", help="Pass Auth to Upstream")
    p_create.add_argument("--cert-id", type=int, default=0)
    p_create.add_argument("--advanced-config", default='')
    p_create.add_argument("--access-list-id", type=int, default=0)
    for act in ["delete", "enable", "disable"]:
        x = p_sub.add_parser(act); x.add_argument("id", type=int)

    p_up = p_sub.add_parser("update")
    p_up.add_argument("id", type=int)
    p_up.add_argument("--domains", nargs='+')
    p_up.add_argument("--ip")
    p_up.add_argument("--port", type=int)
    p_up.add_argument("--scheme", choices=['http', 'https'])
    p_up.add_argument("--ssl-forced", dest='ssl_forced', action="store_true", default=None)
    p_up.add_argument("--no-ssl-forced", dest='ssl_forced', action="store_false")
    p_up.add_argument("--caching", dest='caching', action="store_true", default=None)
    p_up.add_argument("--no-caching", dest='caching', action="store_false")
    p_up.add_argument("--block-exploits", dest='block_exploits', action="store_true", default=None)
    p_up.add_argument("--no-block-exploits", dest='block_exploits', action="store_false")
    p_up.add_argument("--websockets", dest='websockets', action="store_true", default=None)
    p_up.add_argument("--no-websockets", dest='websockets', action="store_false")
    p_up.add_argument("--http2", dest='http2', action="store_true", default=None)
    p_up.add_argument("--no-http2", dest='http2', action="store_false")
    p_up.add_argument("--hsts", dest='hsts', action="store_true", default=None)
    p_up.add_argument("--no-hsts", dest='hsts', action="store_false")
    p_up.add_argument("--pass-auth", dest='pass_auth', action="store_true", default=None)
    p_up.add_argument("--no-pass-auth", dest='pass_auth', action="store_false")
    p_up.add_argument("--access-list-id", type=int)

    # REDIRECT
    r = subparsers.add_parser("redirect", help="Manage Redirection Hosts")
    r_sub = r.add_subparsers(dest="action", required=True)
    r_sub.add_parser("list")
    r_create = r_sub.add_parser("create")
    r_create.add_argument("--domains", nargs='+', required=True)
    r_create.add_argument("--forward-domain", required=True)
    r_create.add_argument("--http-code", type=int, default=301)
    r_create.add_argument("--scheme", choices=['http', 'https', 'auto'], default='auto')
    r_create.add_argument("--preserve-path", action="store_true")
    for act in ["delete", "enable", "disable"]:
        x = r_sub.add_parser(act); x.add_argument("id", type=int)

    r_up = r_sub.add_parser("update")
    r_up.add_argument("id", type=int)
    r_up.add_argument("--domains", nargs='+')
    r_up.add_argument("--forward-domain")
    r_up.add_argument("--http-code", type=int)
    r_up.add_argument("--scheme", choices=['http', 'https', 'auto'])

    # 404
    d = subparsers.add_parser("404", help="Manage 404 Hosts")
    d_sub = d.add_subparsers(dest="action", required=True)
    d_sub.add_parser("list")
    d_create = d_sub.add_parser("create")
    d_create.add_argument("--domains", nargs='+', required=True)
    for act in ["delete", "enable", "disable"]:
        x = d_sub.add_parser(act); x.add_argument("id", type=int)

    d_up = d_sub.add_parser("update")
    d_up.add_argument("id", type=int)
    d_up.add_argument("--domains", nargs='+')

    # STREAM
    s = subparsers.add_parser("stream", help="Manage Streams")
    s_sub = s.add_subparsers(dest="action", required=True)
    s_sub.add_parser("list")
    s_create = s_sub.add_parser("create")
    s_create.add_argument("--incoming-port", type=int, required=True)
    s_create.add_argument("--forward-host", required=True)
    s_create.add_argument("--forward-port", type=int, required=True)
    s_create.add_argument("--tcp", action="store_true", default=True)
    s_create.add_argument("--no-tcp", action="store_false", dest="tcp")
    s_create.add_argument("--udp", action="store_true")
    for act in ["delete", "enable", "disable"]:
        x = s_sub.add_parser(act); x.add_argument("id", type=int)

    s_up = s_sub.add_parser("update")
    s_up.add_argument("id", type=int)
    s_up.add_argument("--incoming-port", type=int)
    s_up.add_argument("--forward-host")
    s_up.add_argument("--forward-port", type=int)
    s_up.add_argument("--tcp", action="store_true", default=None)
    s_up.add_argument("--udp", action="store_true", default=None)

    # CERT
    c = subparsers.add_parser("cert", help="Manage Certificates")
    c_sub = c.add_subparsers(dest="action", required=True)
    c_sub.add_parser("list")
    c_sub.add_parser("providers")
    c_search = c_sub.add_parser("search")
    c_search.add_argument("query")

    # HTTP Create
    c_http = c_sub.add_parser("create-http")
    c_http.add_argument("--domains", nargs='+', required=True)
    c_http.add_argument("--email", required=True, help="Ignored by API, uses logged in user")

    # DNS Create
    c_dns = c_sub.add_parser("create-dns")
    c_dns.add_argument("--domains", nargs='+', required=True)
    c_dns.add_argument("--email", required=True, help="Ignored by API, uses logged in user")
    c_dns.add_argument("--provider", required=True)
    c_dns.add_argument("--credentials", required=True)
    c_dns.add_argument("--propagation", type=int, default=120)

    c_del = c_sub.add_parser("delete"); c_del.add_argument("id", type=int)
    c_renew = c_sub.add_parser("renew"); c_renew.add_argument("id", type=int)
    c_dl = c_sub.add_parser("download"); c_dl.add_argument("id", type=int)

    c_up = c_sub.add_parser("upload"); c_up.add_argument("--payload", required=True, help="JSON payload")
    c_val = c_sub.add_parser("validate"); c_val.add_argument("--payload", required=True, help="JSON payload")
    c_test = c_sub.add_parser("test-http"); c_test.add_argument("--payload", required=True, help="JSON payload")

    # USER
    u = subparsers.add_parser("user", help="Manage Users")
    u_sub = u.add_subparsers(dest="action", required=True)
    u_sub.add_parser("list")
    u_search = u_sub.add_parser("search"); u_search.add_argument("query")
    u_create = u_sub.add_parser("create")
    u_create.add_argument("--name", required=True)
    u_create.add_argument("--nickname", required=True)
    u_create.add_argument("--email", required=True)
    u_create.add_argument("--password", required=True)
    u_create.add_argument("--admin", action="store_true")
    u_del = u_sub.add_parser("delete"); u_del.add_argument("id", type=int)
    u_pw = u_sub.add_parser("reset-password")
    u_pw.add_argument("id", type=int)
    u_pw.add_argument("password")

    u_up = u_sub.add_parser("update")
    u_up.add_argument("id", type=int)
    u_up.add_argument("--name")
    u_up.add_argument("--email")

    u_perm = u_sub.add_parser("permissions")
    u_perm.add_argument("id", type=int)
    u_perm.add_argument("--json", required=True, help="Permissions JSON")

    # REPORT
    rp = subparsers.add_parser("report", help="View Reports")
    rp_sub = rp.add_subparsers(dest="action", required=True)
    rp_sub.add_parser("hosts")

    # SETTING
    st = subparsers.add_parser("setting", help="Manage Settings")
    st_sub = st.add_subparsers(dest="action", required=True)
    st_sub.add_parser("list")
    st_up = st_sub.add_parser("update")
    st_up.add_argument("id", type=str)
    st_up.add_argument("--value", required=True, choices=['congratulations', '404', '444', 'redirect', 'html'])
    st_up.add_argument("--meta-redirect", help="Redirect URL (required for 'redirect')")
    st_up.add_argument("--meta-html", help="HTML Content (required for 'html')")

    # SYSTEM
    sys_p = subparsers.add_parser("system", help="System Info")
    sys_sub = sys_p.add_subparsers(dest="action", required=True)
    sys_sub.add_parser("version")
    sys_sub.add_parser("schema")

    args = parser.parse_args()
    if args.category is None: parser.print_help(); sys.exit(1)

    client = NPMClient()

    if args.category == "audit":
        output_result(generate_audit_json(client), [], True)
        sys.exit(0)

    # LOGIC
    if args.category == "acl":
        if args.action == "list":
            output_result(client.list_access_lists(), ["id", "name", "created_on"], args.json)
        elif args.action == "create":
            items = []
            if args.username and args.password:
                items.append({"username": args.username, "password": args.password})
            client.create_access_list({
                "name": args.name,
                "satisfy_any": args.satisfy_any,
                "items": items,
                "clients": []
            })
            print("Created.")
        elif args.action == "delete":
            client.delete_access_list(args.id); print("Deleted.")
        elif args.action == "update":
            current = client.get_access_list(args.id)
            if args.name: current['name'] = args.name
            if args.satisfy_any is not None:
                current['satisfy_any'] = args.satisfy_any
            if args.items: current['items'] = json.loads(args.items)

            if args.username:
                if 'items' not in current: current['items'] = []
                found = False
                for item in current['items']:
                    if item.get('username') == args.username:
                        if args.password:
                            item['password'] = args.password
                        found = True
                        break
                if not found:
                    if not args.password:
                        print("Error: --password is required when adding a new user.")
                        sys.exit(1)
                    current['items'].append({"username": args.username, "password": args.password})

            # API requires clients list usually
            if 'clients' not in current: current['clients'] = []
            client.update_access_list(args.id, current)
            print("Updated.")

    elif args.category == "proxy":
        ep = "nginx/proxy-hosts"
        if args.action in ["list", "search"]:
            d = filter_data(client.list_items(ep), args.query if args.action == 'search' else None, ['domain_names', 'forward_host'])
            if not args.json:
                for i in d:
                    i['domains'] = "\n".join(i.get('domain_names',[]))
                    i['target'] = f"{i.get('forward_scheme')}://{i.get('forward_host')}:{i.get('forward_port')}"
                    i['ssl'] = "Yes" if i.get('ssl_forced') else "No"
                    i['opts'] = f"WS:{i.get('allow_websocket_upgrade')} H2:{i.get('http2_support')}"
            output_result(d, ["id", "domains", "target", "opts", "enabled"], args.json)
        elif args.action == "create":
            client.create_proxy({
                "domain_names": args.domains, "forward_scheme": args.scheme,
                "forward_host": args.ip, "forward_port": args.port,
                "ssl_forced": args.ssl_forced, "caching_enabled": args.caching,
                "block_exploits": args.block_exploits, "allow_websocket_upgrade": args.websockets,
                "http2_support": args.http2, "hsts_enabled": args.hsts, "hsts_subdomains": False,
                "access_list_id": args.access_list_id, "certificate_id": args.cert_id,
                "meta": {"pass_auth_to_upstream": args.pass_auth}, "advanced_config": args.advanced_config, "locations": []
            })
            print("Created.")
        elif args.action == "delete":
            client.delete_item(ep, args.id); print("Deleted.")
        elif args.action in ["enable", "disable"]:
            client.toggle_enable(ep, args.id, args.action); print(f"{args.action}d.")
        elif args.action == "update":
            # Fetch existing to merge
            # Note: get_proxy takes domain, but we have ID.
            # We must iterate list to find by ID or use a hypothetical get_proxy_by_id if it existed.
            # npm_api.py doesn't have get_proxy_by_id. We iterate list.
            current = None
            for i in client.list_items(ep):
                if i['id'] == args.id: current = i; break
            if not current: print("Host not found."); sys.exit(1)

            if args.domains: current['domain_names'] = args.domains
            if args.ip: current['forward_host'] = args.ip
            if args.port: current['forward_port'] = args.port
            if args.scheme: current['forward_scheme'] = args.scheme
            if args.access_list_id is not None: current['access_list_id'] = args.access_list_id
            # Toggles
            if args.ssl_forced is not None: current['ssl_forced'] = args.ssl_forced
            if args.caching is not None: current['caching_enabled'] = args.caching
            if args.block_exploits is not None: current['block_exploits'] = args.block_exploits
            if args.websockets is not None: current['allow_websocket_upgrade'] = args.websockets
            if args.http2 is not None: current['http2_support'] = args.http2
            if args.hsts is not None: current['hsts_enabled'] = args.hsts
            if args.pass_auth is not None:
                if not current.get('meta'): current['meta'] = {}
                current['meta']['pass_auth_to_upstream'] = args.pass_auth

            client.update_proxy(args.id, current)
            print("Updated.")

    elif args.category == "redirect":
        ep = "nginx/redirection-hosts"
        if args.action == "list":
            d = client.list_items(ep)
            if not args.json:
                for i in d: i['domains'] = "\n".join(i['domain_names'])
            output_result(d, ["id", "domains", "forward_domain_name", "forward_http_code", "enabled"], args.json)
        elif args.action == "create":
            client.create_redirect({
                "domain_names": args.domains, "forward_domain_name": args.forward_domain,
                "forward_http_code": args.http_code, "forward_scheme": args.scheme,
                "preserve_path": args.preserve_path, "block_exploits": False,
                "certificate_id": 0, "ssl_forced": False, "meta": {}, "advanced_config": ""
            })
            print("Created.")
        elif args.action == "delete":
            client.delete_item(ep, args.id); print("Deleted.")
        elif args.action in ["enable", "disable"]:
            client.toggle_enable(ep, args.id, args.action); print(f"{args.action}d.")
        elif args.action == "update":
            current = None
            for i in client.list_items(ep):
                if i['id'] == args.id: current = i; break
            if not current: print("Host not found."); sys.exit(1)

            if args.domains: current['domain_names'] = args.domains
            if args.forward_domain: current['forward_domain_name'] = args.forward_domain
            if args.http_code: current['forward_http_code'] = args.http_code
            if args.scheme: current['forward_scheme'] = args.scheme
            client.update_redirect(args.id, current)
            print("Updated.")

    elif args.category == "404":
        ep = "nginx/dead-hosts"
        if args.action == "list":
            d = client.list_items(ep)
            if not args.json:
                for i in d: i['domains'] = "\n".join(i['domain_names'])
            output_result(d, ["id", "domains", "enabled"], args.json)
        elif args.action == "create":
            client.create_dead({
                "domain_names": args.domains, "certificate_id": 0, "ssl_forced": False,
                "hsts_enabled": False, "hsts_subdomains": False, "http2_support": False,
                "advanced_config": "", "meta": {}
            })
            print("Created.")
        elif args.action == "delete":
            client.delete_item(ep, args.id); print("Deleted.")
        elif args.action == "update":
            current = None
            for i in client.list_items(ep):
                if i['id'] == args.id: current = i; break
            if not current: print("Host not found."); sys.exit(1)

            if args.domains: current['domain_names'] = args.domains
            client.update_dead(args.id, current)
            print("Updated.")

    elif args.category == "stream":
        ep = "nginx/streams"
        if args.action == "list":
            output_result(client.list_items(ep), ["id", "incoming_port", "forwarding_host", "forwarding_port", "tcp_forwarding", "udp_forwarding", "enabled"], args.json)
        elif args.action == "create":
            client.create_stream({
                "incoming_port": args.incoming_port, "forwarding_host": args.forward_host,
                "forwarding_port": args.forward_port, "tcp_forwarding": args.tcp,
                "udp_forwarding": args.udp, "certificate_id": 0, "meta": {}
            })
            print("Created.")
        elif args.action == "delete":
            client.delete_item(ep, args.id); print("Deleted.")
        elif args.action == "update":
            current = client.get_stream(args.id) # get_stream takes port, not ID?
            # npm_api.py get_stream takes in_port. We have ID.
            # Fallback to list search
            current = None
            for i in client.list_items(ep):
                if i['id'] == args.id: current = i; break
            if not current: print("Stream not found."); sys.exit(1)

            if args.incoming_port: current['incoming_port'] = args.incoming_port
            client.update_stream(args.id, current)
            print("Updated.")

    elif args.category == "cert":
        ep = "nginx/certificates"
        if args.action in ["list", "search"]:
            d = filter_data(client.list_items(ep), args.query if args.action == 'search' else None, ['domain_names', 'nice_name'])
            if not args.json:
                for i in d: i['domains'] = "\n".join(i['domain_names'])
            output_result(d, ["id", "provider", "nice_name", "domains", "expires_on"], args.json)
        elif args.action == "providers":
            output_result(client.list_items(f"{ep}/dns-providers"), ["id", "name", "credentials"], args.json)
        elif args.action == "create-http":
            # Idempotency Check
            existing = client.get_cert(args.domains[0])
            if existing:
                print(f"Certificate for '{args.domains[0]}' already exists (ID: {existing['id']}).")
                sys.exit(0) # Exit successfully

            client.create_cert({
                "domain_names": args.domains,
                "provider": "letsencrypt",
                "meta": {
                    "dns_challenge": False
                    # Email/TOS removed based on browser capture
                }
            })
            print("Requested.")
        elif args.action == "create-dns":
            # Idempotency Check
            existing = client.get_cert(args.domains[0])
            if existing:
                print(f"Certificate for '{args.domains[0]}' already exists (ID: {existing['id']}).")
                sys.exit(0) # Exit successfully

            creds = args.credentials
            if os.path.exists(creds):
                with open(creds, 'r') as f: creds = f.read().strip()

            client.create_cert({
                "domain_names": args.domains,
                "provider": "letsencrypt",
                "meta": {
                    "dns_challenge": True,
                    "dns_provider": args.provider,
                    "dns_provider_credentials": creds,
                    "propagation_seconds": args.propagation
                    # Email/TOS removed based on browser capture
                }
            })
            print("Requested.")
        elif args.action == "delete":
            client.delete_item(ep, args.id); print("Deleted.")
        elif args.action == "renew":
            client.session.post(f"{client.base_url}/{ep}/{args.id}/renew"); print("Renew Requested.")
        elif args.action == "download":
            try:
                print(client.download_certificate(args.id))
            except Exception as e:
                print(f"Error: {e}")
        elif args.action == "upload":
            print(client.upload_certificate(json.loads(args.payload)))
        elif args.action == "validate":
            print(client.validate_certificate(json.loads(args.payload)))
        elif args.action == "test-http":
            print(client.test_http_challenge(json.loads(args.payload)))

    elif args.category == "user":
        ep = "users"
        if args.action in ["list", "search"]:
            d = filter_data(client.list_items(ep), args.query if args.action == 'search' else None, ['name', 'email'])
            output_result(d, ["id", "name", "email", "roles"], args.json)
        elif args.action == "create":
            client.create_user({
                "name": args.name, "nickname": args.nickname, "email": args.email,
                "roles": ["admin"] if args.admin else [], "is_disabled": False,
                "auth": {"type": "password", "secret": args.password}
            })
            print("Created.")
        elif args.action == "delete":
            client.delete_item(ep, args.id); print("Deleted.")
        elif args.action == "reset-password":
            client.update_user_auth(args.id, args.password)
            print("Password updated.")
        elif args.action == "update":
            current = client.get_user_by_id(args.id)
            if args.name: current['name'] = args.name
            if args.email: current['email'] = args.email
            client.update_user(args.id, current)
            print("Updated.")
        elif args.action == "permissions":
            client.update_user_permissions(args.id, json.loads(args.json))
            print("Permissions updated.")

    elif args.category == "report":
        if args.action == "hosts":
            output_result(client.get_hosts_report(), [], True)

    elif args.category == "setting":
        if args.action == "list":
            output_result(client.list_settings(), ["id", "name", "value"], args.json)
        elif args.action == "update":
            current = client.get_setting(args.id)
            current['value'] = args.value

            # Handle Meta fields for default-site configuration
            if args.value in ['redirect', 'html']:
                if not current.get('meta'): current['meta'] = {}

                if args.value == 'redirect':
                    if not args.meta_redirect:
                        print("Error: --meta-redirect is required when value is 'redirect'.")
                        sys.exit(1)
                    current['meta']['redirect'] = args.meta_redirect
                elif args.value == 'html':
                    if not args.meta_html:
                        print("Error: --meta-html is required when value is 'html'.")
                        sys.exit(1)
                    current['meta']['html'] = args.meta_html

            client.update_setting(args.id, current)
            print("Updated.")

    elif args.category == "system":
        if args.action == "version":
            print(json.dumps(client.version_check(), indent=2))
        elif args.action == "schema":
            print(json.dumps(client.get_schema(), indent=2))

if __name__ == "__main__":
    main()
