#!/usr/bin/python
from __future__ import absolute_import, division, print_function

__metaclass__ = type
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.egandro.nginx_proxy_manager_tool.plugins.module_utils.npm_api import NPMClient


def run_module():
    module = AnsibleModule(
        argument_spec=dict(
            url=dict(type="str", required=True),
            email=dict(type="str", required=True),
            password=dict(type="str", required=True, no_log=True),
            state=dict(type="str", choices=["present", "absent"], default="present"),
            # Dead Host Details
            domain=dict(type="str", required=True),
            certificate_id=dict(type="int", default=0),
            ssl_forced=dict(type="bool", default=False),
            hsts_enabled=dict(type="bool", default=False),
            hsts_subdomains=dict(type="bool", default=False),
            http2_support=dict(type="bool", default=False),
            advanced_config=dict(type="str", default=""),
            enabled=dict(type="bool", default=True),
        ),
        supports_check_mode=True,
    )

    try:
        client = NPMClient(module.params["url"], module.params["email"], module.params["password"])
    except Exception as e:
        module.fail_json(msg=str(e))

    domain = module.params["domain"]
    state = module.params["state"]

    # 1. Lookup
    existing = client.get_dead(domain)
    result = dict(changed=False)

    # 2. Delete Logic
    if state == "absent":
        if existing:
            if not module.check_mode:
                client.delete_item("nginx/dead-hosts", existing["id"])
            result["changed"] = True
            result["msg"] = f"Dead Host {domain} deleted."
        else:
            result["msg"] = "Dead Host not found."

    # 3. Create/Update Logic
    elif state == "present":
        # Construct Payload
        payload = {
            "domain_names": existing.get("domain_names", [domain]) if existing else [domain],
            "certificate_id": module.params["certificate_id"],
            "ssl_forced": module.params["ssl_forced"],
            "hsts_enabled": module.params["hsts_enabled"],
            "hsts_subdomains": module.params["hsts_subdomains"],
            "http2_support": module.params["http2_support"],
            "advanced_config": module.params["advanced_config"],
            "meta": existing.get("meta", {}) if existing else {},
        }

        if not existing:
            # CREATE
            if not module.check_mode:
                res = client.create_dead(payload)
                result["id"] = res["id"]

                # Handle enabled state if user wants it disabled on creation
                if not module.params["enabled"]:
                    client.disable_dead_host(res["id"])

            result["changed"] = True
            result["msg"] = f"Dead Host {domain} created."
        else:
            result["id"] = existing["id"]
            diff_fields = []

            # Check Fields
            checks = {
                "certificate_id": payload["certificate_id"],
                "ssl_forced": payload["ssl_forced"],
                "hsts_enabled": payload["hsts_enabled"],
                "hsts_subdomains": payload["hsts_subdomains"],
                "http2_support": payload["http2_support"],
                "advanced_config": payload["advanced_config"],
            }

            for field, desired in checks.items():
                current_val = existing.get(field)
                if current_val != desired:
                    diff_fields.append(f"{field}: {current_val} -> {desired}")

            # Check Enabled State
            current_enabled = existing.get("enabled")
            desired_enabled = module.params["enabled"]
            if int(current_enabled) != int(desired_enabled):
                diff_fields.append(f"enabled: {current_enabled} -> {desired_enabled}")

            if diff_fields:
                if not module.check_mode:
                    # Update configuration if needed
                    config_changed = any(k in str(diff_fields) for k in checks.keys())
                    if config_changed:
                        client.update_dead(existing["id"], payload)

                    # Update enabled state if needed
                    if int(current_enabled) != int(desired_enabled):
                        if desired_enabled:
                            client.enable_dead_host(existing["id"])
                        else:
                            client.disable_dead_host(existing["id"])

                result["changed"] = True
                result["msg"] = f"Updated: {', '.join(diff_fields)}"

    module.exit_json(**result)


if __name__ == "__main__":
    run_module()
