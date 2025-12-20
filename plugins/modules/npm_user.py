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

            # User Details
            target_email=dict(type='str', required=True),
            target_name=dict(type='str'),
            target_nickname=dict(type='str'),
            target_password=dict(type='str', no_log=True),

            # Roles / Status
            is_admin=dict(type='bool', default=False),
            is_disabled=dict(type='bool', default=False),

            # Granular Permissions (Optional)
            permissions=dict(type='dict')
        ),
        supports_check_mode=True
    )

    try:
        client = NPMClient(module.params['url'], module.params['email'], module.params['password'])
    except Exception as e:
        module.fail_json(msg=str(e))

    target_email = module.params['target_email']
    state = module.params['state']

    # 1. Lookup
    existing = client.get_user(target_email)
    result = dict(changed=False)

    # 2. Delete Logic
    if state == 'absent':
        if existing:
            if not module.check_mode:
                client.delete_user(existing['id'])
            result['changed'] = True
            result['msg'] = f"User {target_email} deleted."
        else:
            result['msg'] = "User not found."

    # 3. Create/Update Logic
    elif state == 'present':
        target_name = module.params['target_name']
        target_nickname = module.params['target_nickname']
        target_password = module.params['target_password']
        is_admin = module.params['is_admin']
        is_disabled = module.params['is_disabled']
        permissions = module.params['permissions']

        if not existing:
            # CREATE
            if not target_name or not target_password:
                module.fail_json(msg="target_name and target_password are required for creating a user.")

            if not target_nickname:
                target_nickname = target_name

            payload = {
                "name": target_name,
                "nickname": target_nickname,
                "email": target_email,
                "roles": ["admin"] if is_admin else [],
                "is_disabled": is_disabled,
                "auth": {"type": "password", "secret": target_password}
            }

            if not module.check_mode:
                res = client.create_user(payload)
                result['id'] = res['id']

                # Apply permissions if provided
                if permissions:
                    client.update_user_permissions(res['id'], permissions)

            result['changed'] = True
            result['msg'] = f"User {target_email} created."
        else:
            # UPDATE
            result['id'] = existing['id']
            diff_fields = []

            # Prepare update payload based on existing data
            # Check basic fields
            if target_name and existing.get('name') != target_name:
                diff_fields.append(f"name: {existing.get('name')} -> {target_name}")
                existing['name'] = target_name

            if target_nickname and existing.get('nickname') != target_nickname:
                diff_fields.append(f"nickname: {existing.get('nickname')} -> {target_nickname}")
                existing['nickname'] = target_nickname

            # Check Roles
            current_roles = existing.get('roles', [])
            has_admin = 'admin' in current_roles
            if has_admin != is_admin:
                diff_fields.append(f"is_admin: {has_admin} -> {is_admin}")
                if is_admin:
                    if 'admin' not in current_roles: current_roles.append('admin')
                else:
                    if 'admin' in current_roles: current_roles.remove('admin')
                existing['roles'] = current_roles

            # Check Disabled
            if existing.get('is_disabled') != is_disabled:
                diff_fields.append(f"is_disabled: {existing.get('is_disabled')} -> {is_disabled}")
                existing['is_disabled'] = is_disabled

            # Update User Object
            if diff_fields:
                if not module.check_mode:
                    client.update_user(existing['id'], existing)
                result['changed'] = True

            # Update Password (always if provided, as we can't check hash)
            if target_password:
                if not module.check_mode:
                    client.update_user_auth(existing['id'], target_password)
                result['changed'] = True
                diff_fields.append("password updated")

            # Update Permissions
            if permissions:
                # Check if permissions actually changed
                current_perms = existing.get('permissions', {})
                # Simple comparison (keys/values must match exactly)
                # Note: API might return defaults that are not in input, so this is a loose check.
                # Ideally we only compare keys present in 'permissions'.
                perms_changed = False
                for k, v in permissions.items():
                    if current_perms.get(k) != v:
                        perms_changed = True
                        break

                if perms_changed:
                    if not module.check_mode:
                        client.update_user_permissions(existing['id'], permissions)
                    result['changed'] = True
                    diff_fields.append("permissions updated")

            if result['changed']:
                result['msg'] = f"Updated: {', '.join(diff_fields)}"

    module.exit_json(**result)

if __name__ == '__main__':
    run_module()
