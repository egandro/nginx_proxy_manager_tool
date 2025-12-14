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
            target_email=dict(type='str', required=True),
            target_name=dict(type='str'),
            target_password=dict(type='str', no_log=True),
            is_admin=dict(type='bool', default=False),
        ),
        supports_check_mode=True
    )

    try:
        client = NPMClient(module.params['url'], module.params['email'], module.params['password'])
    except Exception as e:
        module.fail_json(msg=str(e))

    t_email = module.params['target_email']
    existing = client.get_user(t_email)
    result = dict(changed=False)

    if module.params['state'] == 'absent':
        if existing:
            if not module.check_mode: client.delete_item("users", existing['id'])
            result['changed'] = True
    else:
        if not existing:
            payload = {
                "name": module.params['target_name'],
                "nickname": module.params['target_name'].split()[0],
                "email": t_email,
                "roles": ["admin"] if module.params['is_admin'] else [],
                "is_disabled": False,
                "auth": {"type": "password", "secret": module.params['target_password']}
            }
            if not module.check_mode: client.create_user(payload)
            result['changed'] = True
        else:
            # Update info
            payload = {
                "name": module.params['target_name'],
                "nickname": module.params['target_name'].split()[0],
                "email": t_email,
                "roles": ["admin"] if module.params['is_admin'] else [],
                "is_disabled": False
            }
            if existing['name'] != payload['name'] or existing['roles'] != payload['roles']:
                 if not module.check_mode: client.update_user(existing['id'], payload)
                 result['changed'] = True

            # Update password if provided (Always updates if param is set)
            if module.params['target_password']:
                 if not module.check_mode: client.update_user_auth(existing['id'], module.params['target_password'])
                 result['changed'] = True

    module.exit_json(**result)

if __name__ == '__main__': run_module()
