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
            forward_domain=dict(type='str'),
            forward_http_code=dict(type='int', default=301),
            preserve_path=dict(type='bool', default=False),
        ),
        supports_check_mode=True
    )

    try:
        client = NPMClient(module.params['url'], module.params['email'], module.params['password'])
    except Exception as e:
        module.fail_json(msg=str(e))

    domain = module.params['domain']
    existing = client.get_redirect(domain)
    result = dict(changed=False)

    if module.params['state'] == 'absent':
        if existing:
            if not module.check_mode: client.delete_item("nginx/redirection-hosts", existing['id'])
            result['changed'] = True
    else:
        payload = {
            "domain_names": [domain],
            "forward_domain_name": module.params['forward_domain'],
            "forward_http_code": module.params['forward_http_code'],
            "forward_scheme": "auto",
            "preserve_path": module.params['preserve_path'],
            "block_exploits": False, "certificate_id": 0, "ssl_forced": False, "meta": {}, "advanced_config": ""
        }

        if not existing:
            if not module.check_mode: client.create_redirect(payload)
            result['changed'] = True
        else:
            if (existing['forward_domain_name'] != payload['forward_domain_name'] or
                int(existing['forward_http_code']) != int(payload['forward_http_code']) or
                bool(existing['preserve_path']) != payload['preserve_path']):
                if not module.check_mode: client.update_redirect(existing['id'], payload)
                result['changed'] = True

    module.exit_json(**result)

if __name__ == '__main__': run_module()
