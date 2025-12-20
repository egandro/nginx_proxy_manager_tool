def generate_audit_json(client):
    """
    Fetches all data, sanitizes it (removes IDs, dates, passwords),
    resolves relationships (ID -> Name), and returns a clean dictionary.
    """
    # Fetch data
    raw_users = client.list_items("users")
    raw_certs = client.list_items("nginx/certificates")
    raw_acls = client.list_items("nginx/access-lists")
    raw_proxies = client.list_items("nginx/proxy-hosts")
    raw_redirects = client.list_items("nginx/redirection-hosts")
    raw_streams = client.list_items("nginx/streams")
    raw_dead = client.list_items("nginx/dead-hosts")
    raw_settings = client.list_settings()

    # Maps for resolution
    user_map = {u["id"]: u["email"] for u in raw_users}
    cert_map = {c["id"]: c.get("nice_name", "Unknown") for c in raw_certs}
    acl_map = {a["id"]: a["name"] for a in raw_acls}

    # Cleaner helper
    def clean_obj(obj, keys_to_remove):
        for key in keys_to_remove:
            obj.pop(key, None)
        return obj

    base_ignore = ["id", "created_on", "modified_on", "meta", "owner_user_id", "certificate_id", "access_list_id"]

    # Clean Entities
    clean_users = []
    for u in raw_users:
        c = clean_obj(u.copy(), ["id", "created_on", "modified_on", "is_disabled", "avatar"])
        clean_users.append(c)

    clean_certs = []
    for c in raw_certs:
        cl = clean_obj(c.copy(), base_ignore + ["expires_on"])
        cl["owner"] = user_map.get(c.get("owner_user_id"))
        clean_certs.append(cl)

    clean_proxies = []
    for p in raw_proxies:
        cl = clean_obj(p.copy(), base_ignore)
        cl["owner"] = user_map.get(p.get("owner_user_id"))
        cl["certificate_name"] = cert_map.get(p.get("certificate_id"), "None")
        cl["access_list_name"] = acl_map.get(p.get("access_list_id"), "Public")
        clean_proxies.append(cl)

    clean_redirects = []
    for r in raw_redirects:
        cl = clean_obj(r.copy(), base_ignore)
        cl["owner"] = user_map.get(r.get("owner_user_id"))
        clean_redirects.append(cl)

    clean_streams = []
    for s in raw_streams:
        cl = clean_obj(s.copy(), base_ignore)
        cl["owner"] = user_map.get(s.get("owner_user_id"))
        clean_streams.append(cl)

    clean_acls = []
    for a in raw_acls:
        cl = clean_obj(a.copy(), base_ignore)
        cl["owner"] = user_map.get(a.get("owner_user_id"))
        clean_acls.append(cl)

    clean_dead = []
    for d in raw_dead:
        cl = clean_obj(d.copy(), base_ignore)
        cl["owner"] = user_map.get(d.get("owner_user_id"))
        cl["certificate_name"] = cert_map.get(d.get("certificate_id"), "None")
        clean_dead.append(cl)

    clean_settings = []
    for s in raw_settings:
        cl = s.copy()
        for key in ["created_on", "modified_on"]:
            cl.pop(key, None)
        clean_settings.append(cl)

    # Sort for consistent diffs
    clean_users.sort(key=lambda x: x["email"])
    clean_certs.sort(key=lambda x: x.get("nice_name", ""))
    clean_proxies.sort(key=lambda x: x.get("domain_names", [""])[0])
    clean_redirects.sort(key=lambda x: x.get("domain_names", [""])[0])
    clean_streams.sort(key=lambda x: x.get("incoming_port", 0))
    clean_acls.sort(key=lambda x: x.get("name", ""))
    clean_dead.sort(key=lambda x: x.get("domain_names", [""])[0])
    clean_settings.sort(key=lambda x: x.get("id", ""))

    return {
        "summary": {
            "users": len(clean_users),
            "certs": len(clean_certs),
            "proxies": len(clean_proxies),
            "redirects": len(clean_redirects),
            "streams": len(clean_streams),
            "access_lists": len(clean_acls),
            "dead_hosts": len(clean_dead),
            "settings": len(clean_settings),
        },
        "users": clean_users,
        "certificates": clean_certs,
        "proxy_hosts": clean_proxies,
        "redirection_hosts": clean_redirects,
        "streams": clean_streams,
        "access_lists": clean_acls,
        "dead_hosts": clean_dead,
        "settings": clean_settings,
    }
