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

            # Stream Details
            incoming_port=dict(type='int', required=True),
            forward_host=dict(type='str'),
            forward_port=dict(type='int'),
            tcp=dict(type='bool', default=True),
            udp=dict(type='bool', default=False),

            # Common
            enabled=dict(type='bool', default=True)
        ),
        supports_check_mode=True
    )

    try:
        client = NPMClient(module.params['url'], module.params['email'], module.params['password'])
    except Exception as e:
        module.fail_json(msg=str(e))

    incoming_port = module.params['incoming_port']
    state = module.params['state']

    # 1. Lookup
    existing = client.get_stream(incoming_port)
    result = dict(changed=False)

    # 2. Delete Logic
    if state == 'absent':
        if existing:
            if not module.check_mode:
                client.delete_item("nginx/streams", existing['id'])
            result['changed'] = True
            result['msg'] = f"Stream on port {incoming_port} deleted."
        else:
            result['msg'] = "Stream not found."

    # 3. Create/Update Logic
    elif state == 'present':
        # Validation for creation
        if not existing:
            if not module.params['forward_host'] or not module.params['forward_port']:
                module.fail_json(msg="forward_host and forward_port are required for creating a stream.")

        # Construct Payload
        # Use existing values if optional params are missing during update
        forward_host = module.params['forward_host']
        if existing and not forward_host:
            forward_host = existing.get('forwarding_host')

        forward_port = module.params['forward_port']
        if existing and not forward_port:
            forward_port = existing.get('forwarding_port')

        payload = {
            "incoming_port": incoming_port,
            "forwarding_host": forward_host,
            "forwarding_port": forward_port,
            "tcp_forwarding": module.params['tcp'],
            "udp_forwarding": module.params['udp'],
            "certificate_id": 0,
            "meta": existing.get('meta', {}) if existing else {}
        }

        if not existing:
            # CREATE
            if not module.check_mode:
                res = client.create_stream(payload)
                result['id'] = res['id']

                if not module.params['enabled']:
                     client.disable_stream(res['id'])

            result['changed'] = True
            result['msg'] = f"Stream {incoming_port} created."
        else:
            result['id'] = existing['id']
            diff_fields = []

            # Check Fields
            checks = {
                'forwarding_host': payload['forwarding_host'],
                'forwarding_port': payload['forwarding_port'],
                'tcp_forwarding': payload['tcp_forwarding'],
                'udp_forwarding': payload['udp_forwarding']
            }

            for field, desired in checks.items():
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
                        client.update_stream(existing['id'], payload)

                    # Update enabled state if needed
                    if int(current_enabled) != int(desired_enabled):
                        if desired_enabled:
                            client.enable_stream(existing['id'])
                        else:
                            client.disable_stream(existing['id'])

                result['changed'] = True
                result['msg'] = f"Updated: {', '.join(diff_fields)}"

    module.exit_json(**result)

if __name__ == '__main__':
    run_module()
