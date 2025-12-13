#!/usr/bin/python

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from ansible.module_utils.basic import AnsibleModule
# Import the shared class from module_utils
from ansible.module_utils.npm_api import NPMClient

DOCUMENTATION = r'''
module: npm_proxy
short_description: Manage Nginx Proxy Manager Proxy Hosts
options:
  url:
    description: NPM URL
    required: true
    type: str
  email:
    description: NPM Admin Email
    required: true
    type: str
  password:
    description: NPM Admin Password
    required: true
    type: str
  state:
    description: Whether the host should exist or not
    choices: [ present, absent ]
    default: present
  domain:
    description: The main domain name (e.g. app.example.com)
    required: true
    type: str
  forward_host:
    description: Target IP or Hostname
    required: false
    type: str
  forward_port:
    description: Target Port
    required: false
    type: int
  ssl_forced:
    description: Force SSL
    type: bool
    default: false
'''

def run_module():
    module_args = dict(
        url=dict(type='str', required=True),
        email=dict(type='str', required=True),
        password=dict(type='str', required=True, no_log=True),
        state=dict(type='str', choices=['present', 'absent'], default='present'),
        domain=dict(type='str', required=True),
        forward_host=dict(type='str'),
        forward_port=dict(type='int'),
        ssl_forced=dict(type='bool', default=False),
        # Add other fields like caching, block_exploits, etc. as needed
    )

    result = dict(changed=False, message='')

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    # Initialize shared client
    try:
        client = NPMClient(
            url=module.params['url'],
            email=module.params['email'],
            password=module.params['password']
        )
    except Exception as e:
        module.fail_json(msg=f"Failed to connect to NPM: {str(e)}")

    domain = module.params['domain']
    state = module.params['state']

    # Check if host exists
    existing_host = client.get_proxy_by_domain(domain)

    # --- DELETE LOGIC ---
    if state == 'absent':
        if existing_host:
            if not module.check_mode:
                client.delete_item("nginx/proxy-hosts", existing_host['id'])
            result['changed'] = True
            result['message'] = f"Host {domain} deleted."
        else:
            result['message'] = "Host not found, nothing to do."

    # --- CREATE / UPDATE LOGIC ---
    elif state == 'present':
        # Prepare payload
        payload = {
            "domain_names": [domain],
            "forward_scheme": "http", # Defaulting for simplicity
            "forward_host": module.params['forward_host'],
            "forward_port": module.params['forward_port'],
            "ssl_forced": module.params['ssl_forced'],
            "meta": {},
            "advanced_config": "",
            "locations": [],
            "caching_enabled": False,
            "block_exploits": False,
            "allow_websocket_upgrade": False,
            "http2_support": False,
            "hsts_enabled": False,
            "hsts_subdomains": False,
            "access_list_id": 0,
            "certificate_id": 0
        }

        if not existing_host:
            # CREATE
            if not module.check_mode:
                client.create_proxy(payload)
            result['changed'] = True
            result['message'] = f"Host {domain} created."
        else:
            # UPDATE (Idempotency Check)
            # Compare current state with desired state
            needs_update = False
            if existing_host['forward_host'] != payload['forward_host']: needs_update = True
            if existing_host['forward_port'] != payload['forward_port']: needs_update = True
            if bool(existing_host['ssl_forced']) != payload['ssl_forced']: needs_update = True

            if needs_update:
                if not module.check_mode:
                    client.update_proxy(existing_host['id'], payload)
                result['changed'] = True
                result['message'] = f"Host {domain} updated."
            else:
                result['message'] = "Configuration matches, no changes."

    module.exit_json(**result)

if __name__ == '__main__':
    run_module()