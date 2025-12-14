#!/usr/bin/python
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.egandro.nginx_proxy_manager_tool.plugins.module_utils.npm_api import NPMClient
import os

def run_module():
    module = AnsibleModule(
        argument_spec=dict(
            url=dict(type='str', required=True),
            email=dict(type='str', required=True),
            password=dict(type='str', required=True, no_log=True),
            state=dict(type='str', choices=['present', 'absent'], default='present'),

            # Certificate Details
            domain=dict(type='str', required=True), # The primary CN
            extra_domains=dict(type='list', elements='str', default=[]),
            le_email=dict(type='str', required=True), # Used for creation only

            # Provider Details
            provider=dict(type='str', default='letsencrypt'), # 'letsencrypt' or 'cloudflare', etc.
            dns_credentials=dict(type='str', no_log=True), # Raw string or /path/to/file
            propagation=dict(type='int', default=120)
        ),
        supports_check_mode=True
    )

    try:
        client = NPMClient(module.params['url'], module.params['email'], module.params['password'])
    except Exception as e:
        module.fail_json(msg=f"Authentication failed: {str(e)}")

    domain = module.params['domain']

    # 1. Idempotency Check (Lookup by Domain Name)
    existing = client.get_cert(domain)
    result = dict(changed=False)

    # --- DELETE LOGIC ---
    if module.params['state'] == 'absent':
        if existing:
            if not module.check_mode:
                client.delete_item("nginx/certificates", existing['id'])
            result['changed'] = True
            result['msg'] = f"Certificate for {domain} deleted."
        else:
            result['msg'] = "Certificate not found."

    # --- CREATE LOGIC (PRESENT) ---
    else:
        if existing:
            # 2. ABORT IF EXISTS
            # We cannot read the existing DNS credentials/provider from the API (they are redacted).
            # Therefore, we cannot compare 'Current' vs 'Desired' state safely.
            # We assume if the Domain matches, the certificate is correct.
            result['changed'] = False
            result['msg'] = f"Certificate for {domain} already exists. Skipping creation to avoid duplicates/errors."
            result['id'] = existing['id']
        else:
            # 3. CREATE ONLY IF MISSING
            all_domains = [domain] + module.params['extra_domains']

            # Payload matching the JSON structure you captured
            payload = {
                "domain_names": all_domains,
                "provider": "letsencrypt",
                "meta": {}
            }

            if module.params['provider'] == 'letsencrypt':
                # HTTP Challenge
                payload['meta']['dns_challenge'] = False
            else:
                # DNS Challenge
                creds = module.params['dns_credentials']
                # Handle File Path vs Raw String
                if creds and os.path.exists(creds):
                    try:
                        with open(creds, 'r') as f: creds = f.read().strip()
                    except Exception as e:
                        module.fail_json(msg=f"Could not read credential file: {e}")

                payload['meta']['dns_challenge'] = True
                payload['meta']['dns_provider'] = module.params['provider']
                payload['meta']['dns_provider_credentials'] = creds
                payload['meta']['propagation_seconds'] = module.params['propagation']

            if not module.check_mode:
                client.create_cert(payload)

            result['changed'] = True
            result['msg'] = f"Certificate for {domain} created."

    module.exit_json(**result)

if __name__ == '__main__':
    run_module()
