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
except ImportError:
    print("CRITICAL ERROR: Could not import 'NPMClient'.")
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
    p_create.add_argument("--cert-id", type=int, default=0)
    p_create.add_argument("--access-list-id", type=int, default=0)
    for act in ["delete", "enable", "disable"]:
        x = p_sub.add_parser(act); x.add_argument("id", type=int)

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

    # 404
    d = subparsers.add_parser("404", help="Manage 404 Hosts")
    d_sub = d.add_subparsers(dest="action", required=True)
    d_sub.add_parser("list")
    d_create = d_sub.add_parser("create")
    d_create.add_argument("--domains", nargs='+', required=True)
    for act in ["delete", "enable", "disable"]:
        x = d_sub.add_parser(act); x.add_argument("id", type=int)

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

    args = parser.parse_args()
    if args.category is None: parser.print_help(); sys.exit(1)

    client = NPMClient()

    if args.category == "audit":
        output_result(client.generate_audit_json(), [], True)
        sys.exit(0)

    # LOGIC
    if args.category == "proxy":
        ep = "nginx/proxy-hosts"
        if args.action in ["list", "search"]:
            d = filter_data(client.list_items(ep), args.query if args.action == 'search' else None, ['domain_names', 'forward_host'])
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
                "meta": {}, "advanced_config": "", "locations": []
            })
            print("Created.")
        elif args.action == "delete":
            client.delete_item(ep, args.id); print("Deleted.")
        elif args.action in ["enable", "disable"]:
            client.toggle_enable(ep, args.id, args.action); print(f"{args.action}d.")

    elif args.category == "redirect":
        ep = "nginx/redirection-hosts"
        if args.action == "list":
            d = client.list_items(ep)
            for i in d: i['domains'] = "\n".join(i['domain_names'])
            output_result(d, ["id", "domains", "forward_domain_name", "forward_http_code", "enabled"], args.json)
        elif args.action == "create":
            client.create_redirection({
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

    elif args.category == "404":
        ep = "nginx/dead-hosts"
        if args.action == "list":
            d = client.list_items(ep)
            for i in d: i['domains'] = "\n".join(i['domain_names'])
            output_result(d, ["id", "domains", "enabled"], args.json)
        elif args.action == "create":
            client.create_dead_host({
                "domain_names": args.domains, "certificate_id": 0, "ssl_forced": False,
                "hsts_enabled": False, "hsts_subdomains": False, "http2_support": False,
                "advanced_config": "", "meta": {}
            })
            print("Created.")
        elif args.action == "delete":
            client.delete_item(ep, args.id); print("Deleted.")

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

    elif args.category == "cert":
        ep = "nginx/certificates"
        if args.action in ["list", "search"]:
            d = filter_data(client.list_items(ep), args.query if args.action == 'search' else None, ['domain_names', 'nice_name'])
            for i in d: i['domains'] = "\n".join(i['domain_names'])
            output_result(d, ["id", "provider", "nice_name", "domains", "expires_on"], args.json)
        elif args.action == "providers":
            output_result(client.list_items(f"{ep}/dns-providers"), ["id", "name", "credentials"], args.json)
        elif args.action == "create-http":
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

if __name__ == "__main__":
    main()
