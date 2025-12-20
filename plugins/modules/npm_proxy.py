#!/usr/bin/python
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.egandro.nginx_proxy_manager_tool.plugins.module_utils.npm_api import NPMClient

def run_module():
    module = AnsibleModule(
        argument_spec=dict(
            url=dict(type='str', required=True),
            email=dict(type='str', required=True),
            password=dict(type='str', required=True, no_log=True),
            state=dict(type='str', choices=['present', 'absent'], default='present'),
            # Host Details
            domain=dict(type='str', required=True),
            forward_scheme=dict(type='str', choices=['http', 'https'], default='http'),
            forward_host=dict(type='str'),
            forward_port=dict(type='int'),
            # Toggles
            ssl_forced=dict(type='bool', default=False),
            websockets=dict(type='bool', default=False),
            block_exploits=dict(type='bool', default=False),
            caching=dict(type='bool', default=False),
            http2=dict(type='bool', default=False),
            hsts_enabled=dict(type='bool', default=False),
            hsts_subdomains=dict(type='bool', default=False),
            enabled=dict(type='bool', default=True),


            certificate_id=dict(type='int', default=0),
            access_list_id=dict(type='int', default=0),
            advanced_config=dict(type='str', default=''),
        ),
        supports_check_mode=True
    )

    try:
        client = NPMClient(module.params['url'], module.params['email'], module.params['password'])
    except Exception as e:
        module.fail_json(msg=str(e))

    domain = module.params['domain']
    state = module.params['state']

    # 1. Lookup
    existing = client.get_proxy(domain)
    result = dict(changed=False)

    # 2. Delete Logic
    if state == 'absent':
        if existing:
            if not module.check_mode:
                client.delete_item("nginx/proxy-hosts", existing['id'])
            result['changed'] = True
            result['msg'] = f"Host {domain} deleted."
        else:
            result['msg'] = "Host not found."

    # 3. Create/Update Logic
    elif state == 'present':
        # Construct exact API Payload based on Schema
        payload = {
            "domain_names": existing.get('domain_names', [domain]) if existing else [domain],
            "forward_scheme": module.params['forward_scheme'],
            "forward_host": module.params['forward_host'],
            "forward_port": module.params['forward_port'],
            "ssl_forced": module.params['ssl_forced'],
            "allow_websocket_upgrade": module.params['websockets'],
            "block_exploits": module.params['block_exploits'],
            "caching_enabled": module.params['caching'],
            "http2_support": module.params['http2'],
            "hsts_enabled": module.params['hsts_enabled'],
            "hsts_subdomains": module.params['hsts_subdomains'],
            # Optional fields
            "access_list_id": module.params['access_list_id'],
            "certificate_id": module.params['certificate_id'],
            "advanced_config":  module.params['advanced_config'],
            # Defaults for fields we don't manage yet via Ansible
            "meta": existing.get('meta', {}) if existing else {},
            "locations": existing.get('locations', []) if existing else []
        }

        if not existing:
            # CREATE
            if not module.check_mode:
                res = client.create_proxy(payload)
                result['id'] = res['id']

                if not module.params['enabled']:
                    client.disable_proxy_host(res['id'])

            result['changed'] = True
            result['msg'] = f"Host {domain} created."
        else:
            result['id'] = existing['id']

            # UPDATE - Deep Comparison for Idempotency
            # We compare the payload we BUILT against the existing object data
            diff_fields = []

            # Simple fields mapping (API Field -> Desired Value)
            checks = {
                'forward_scheme': payload['forward_scheme'],
                'forward_host': payload['forward_host'],
                'forward_port': payload['forward_port'],
                'ssl_forced': payload['ssl_forced'],
                'allow_websocket_upgrade': payload['allow_websocket_upgrade'],
                'block_exploits': payload['block_exploits'],
                'caching_enabled': payload['caching_enabled'],
                'http2_support': payload['http2_support'],
                'hsts_enabled': payload['hsts_enabled'],
                'hsts_subdomains': payload['hsts_subdomains'],
                'access_list_id': payload['access_list_id'],
                'certificate_id': payload['certificate_id'],
                'advanced_config': payload['advanced_config']
            }

            for field, desired in checks.items():
                # API usually returns ints as ints and bools as bools, but we cast to be safe
                current_val = existing.get(field)
                if current_val != desired:
                    diff_fields.append(f"{field}: {current_val} -> {desired}")

            # Check Enabled State
            current_enabled = existing.get('enabled')
            desired_enabled = module.params['enabled']
            if int(current_enabled) != int(desired_enabled):
                diff_fields.append(f"enabled: {current_enabled} -> {desired_enabled}")

            if diff_fields:
                if not module.check_mode:
                    # Update configuration if needed
                    config_changed = any(k in str(diff_fields) for k in checks.keys())
                    if config_changed:
                        client.update_proxy(existing['id'], payload)

                    if int(current_enabled) != int(desired_enabled):
                        if desired_enabled:
                            client.enable_proxy_host(existing['id'])
                        else:
                            client.disable_proxy_host(existing['id'])
                result['changed'] = True
                result['msg'] = f"Updated: {', '.join(diff_fields)}"

    module.exit_json(**result)

if __name__ == '__main__':
    run_module()
