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
            incoming_port=dict(type='int', required=True),
            forward_host=dict(type='str'),
            forward_port=dict(type='int'),
            tcp=dict(type='bool', default=True),
            udp=dict(type='bool', default=False),
        ),
        supports_check_mode=True
    )

    try:
        client = NPMClient(module.params['url'], module.params['email'], module.params['password'])
    except Exception as e:
        module.fail_json(msg=str(e))

    in_port = module.params['incoming_port']
    existing = client.get_stream(in_port)
    result = dict(changed=False)

    if module.params['state'] == 'absent':
        if existing:
            if not module.check_mode: client.delete_item("nginx/streams", existing['id'])
            result['changed'] = True
    else:
        payload = {
            "incoming_port": in_port,
            "forwarding_host": module.params['forward_host'],
            "forwarding_port": module.params['forward_port'],
            "tcp_forwarding": module.params['tcp'],
            "udp_forwarding": module.params['udp'],
            "certificate_id": 0, "meta": {}
        }

        if not existing:
            if not module.check_mode: client.create_stream(payload)
            result['changed'] = True
        else:
            if (existing['forwarding_host'] != payload['forwarding_host'] or
                int(existing['forwarding_port']) != int(payload['forwarding_port'])):
                if not module.check_mode: client.update_stream(existing['id'], payload)
                result['changed'] = True

    module.exit_json(**result)

if __name__ == '__main__': run_module()
