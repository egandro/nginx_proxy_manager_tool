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
            domain=dict(type='str', required=True),
        ),
        supports_check_mode=True
    )

    try:
        client = NPMClient(module.params['url'], module.params['email'], module.params['password'])
    except Exception as e:
        module.fail_json(msg=str(e))

    domain = module.params['domain']
    existing = client.get_dead(domain)
    result = dict(changed=False)

    if module.params['state'] == 'absent':
        if existing:
            if not module.check_mode: client.delete_item("nginx/dead-hosts", existing['id'])
            result['changed'] = True
    else:
        if not existing:
            payload = {
                "domain_names": [domain],
                "certificate_id": 0, "ssl_forced": False, "hsts_enabled": False,
                "hsts_subdomains": False, "http2_support": False, "advanced_config": "", "meta": {}
            }
            if not module.check_mode: client.create_dead(payload)
            result['changed'] = True

    module.exit_json(**result)

if __name__ == '__main__': run_module()
