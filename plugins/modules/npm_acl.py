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

            name=dict(type='str', required=True),
            satisfy_any=dict(type='bool', default=False),
            users=dict(type='list', elements='dict', options=dict(
                username=dict(type='str', required=True),
                password=dict(type='str', required=True, no_log=True)
            ), default=None)
        ),
        supports_check_mode=True
    )

    try:
        client = NPMClient(module.params['url'], module.params['email'], module.params['password'])
    except Exception as e:
        module.fail_json(msg=str(e))

    name = module.params['name']
    state = module.params['state']

    # 1. Lookup by Name
    # API doesn't support search by name for ACLs, so we list all and filter.
    acls = client.list_access_lists()
    existing = next((item for item in acls if item['name'] == name), None)

    result = dict(changed=False)

    # 2. Delete Logic
    if state == 'absent':
        if existing:
            if not module.check_mode:
                client.delete_access_list(existing['id'])
            result['changed'] = True
            result['msg'] = f"Access List {name} deleted."
        else:
            result['msg'] = "Access List not found."

    # 3. Create/Update Logic
    elif state == 'present':
        # Prepare Items (Users)
        # If users param is provided, we enforce it. If None, we default to empty on create, or preserve on update.
        desired_items = []
        if module.params['users'] is not None:
            for u in module.params['users']:
                desired_items.append({
                    "username": u['username'],
                    "password": u['password']
                })

        # Construct Payload
        # Note: 'clients' (IP ranges) are not currently supported by this module arguments,
        # so we default to empty on create, or preserve existing on update.
        payload = {
            "name": name,
            "satisfy_any": module.params['satisfy_any'],
            "items": desired_items,
            "clients": []
        }

        if not existing:
            # CREATE
            if module.params['users'] is None:
                payload['items'] = []

            if not module.check_mode:
                res = client.create_access_list(payload)
                result['id'] = res['id']

            result['changed'] = True
            result['msg'] = f"Access List {name} created."
        else:
            result['id'] = existing['id']

            # Preserve existing clients/items if not managed
            payload['clients'] = existing.get('clients', [])
            if module.params['users'] is None:
                payload['items'] = existing.get('items', [])

            # Diff Logic
            diff_fields = []

            if existing.get('satisfy_any') != payload['satisfy_any']:
                diff_fields.append(f"satisfy_any: {existing.get('satisfy_any')} -> {payload['satisfy_any']}")

            # Check Items (Users)
            # If users were provided, we compare.
            # Since we can't compare plain password to hash, we assume change if users are provided.
            # To be slightly smarter, we could check if usernames match, but that doesn't account for password updates.
            # So, if 'users' is defined, we effectively always update unless we implement a complex hash check (not possible here).
            if module.params['users'] is not None:
                # We assume changed because we want to enforce passwords
                # Ideally we would only update if usernames changed OR force=yes, but for now we enforce state.
                # To reduce noise, one could check if usernames are identical and skip, but that prevents password rotation.
                diff_fields.append("users (enforced)")

            if diff_fields:
                if not module.check_mode:
                    client.update_access_list(existing['id'], payload)
                result['changed'] = True
                result['msg'] = f"Updated: {', '.join(diff_fields)}"

    module.exit_json(**result)

if __name__ == '__main__':
    run_module()