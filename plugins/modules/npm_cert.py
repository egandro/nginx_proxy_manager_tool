#!/usr/bin/python
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.npm_api import NPMClient
import os

def run_module():
    module = AnsibleModule(
        argument_spec=dict(
            url=dict(type='str', required=True),
            email=dict(type='str', required=True),
            password=dict(type='str', required=True, no_log=True),
            state=dict(type='str', choices=['present', 'absent'], default='present'),
            domain=dict(type='str', required=True), # Main domain
            extra_domains=dict(type='list', elements='str', default=[]),
            le_email=dict(type='str', required=True),
            provider=dict(type='str', default='letsencrypt'), # 'letsencrypt' (http) or dns provider code
            dns_credentials=dict(type='str', no_log=True), # Raw string or path
            propagation=dict(type='int', default=120)
        ),
        supports_check_mode=True
    )

    try:
        client = NPMClient(module.params['url'], module.params['email'], module.params['password'])
    except Exception as e:
        module.fail_json(msg=str(e))

    domain = module.params['domain']
    all_domains = [domain] + module.params['extra_domains']
    existing = client.get_cert(domain)
    result = dict(changed=False)

    if module.params['state'] == 'absent':
        if existing:
            if not module.check_mode: client.delete_item("nginx/certificates", existing['id'])
            result['changed'] = True
    else:
        if not existing:
            # Determine if HTTP or DNS challenge
            payload = {
                "domain_names": all_domains,
                "provider": "letsencrypt",
                "meta": {
                    "letsencrypt_email": module.params['le_email'],
                    "agree_tos": True
                }
            }

            if module.params['provider'] == 'letsencrypt':
                # HTTP Challenge
                payload['meta']['dns_challenge'] = False
            else:
                # DNS Challenge
                creds = module.params['dns_credentials']
                if creds and os.path.exists(creds):
                    with open(creds, 'r') as f: creds = f.read().strip()

                payload['meta']['dns_challenge'] = True
                payload['meta']['dns_provider'] = module.params['provider']
                payload['meta']['dns_provider_credentials'] = creds
                payload['meta']['propagation_seconds'] = module.params['propagation']

            if not module.check_mode: client.create_cert(payload)
            result['changed'] = True

    module.exit_json(**result)

if __name__ == '__main__': run_module()
