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

            name=dict(type='str', required=True), # The setting ID (e.g. 'default-site')
            value=dict(type='raw', required=True), # The value to set (bool, str, int, etc.)
            meta_redirect=dict(type='str'),
            meta_html=dict(type='str'),
        ),
        supports_check_mode=True
    )

    try:
        client = NPMClient(module.params['url'], module.params['email'], module.params['password'])
    except Exception as e:
        module.fail_json(msg=str(e))

    setting_id = module.params['name']
    desired_value = module.params['value']
    meta_redirect = module.params['meta_redirect']
    meta_html = module.params['meta_html']

    # Validation for default-site specific values
    # We cast to string for comparison because desired_value is 'raw'
    if str(desired_value) == 'redirect' and not meta_redirect:
        module.fail_json(msg="meta_redirect is required when value is 'redirect'")
    if str(desired_value) == 'html' and not meta_html:
        module.fail_json(msg="meta_html is required when value is 'html'")

    # 1. Lookup
    try:
        current = client.get_setting(setting_id)
    except Exception:
        module.fail_json(msg=f"Setting '{setting_id}' not found or API error.")

    result = dict(changed=False)

    # 2. Compare and Update
    current_val = current.get('value')

    # Basic Type Coercion to match existing type if possible
    # This helps when Ansible passes 'true' (str) but API expects True (bool)
    if current_val is not None:
        if isinstance(current_val, bool) and not isinstance(desired_value, bool):
             if str(desired_value).lower() in ['true', 'yes', '1']:
                 desired_value = True
             elif str(desired_value).lower() in ['false', 'no', '0']:
                 desired_value = False
        elif isinstance(current_val, int) and not isinstance(desired_value, int):
            try:
                desired_value = int(desired_value)
            except ValueError:
                pass
        # If current is string, we assume desired is string or convertible
        elif isinstance(current_val, str) and not isinstance(desired_value, str):
            desired_value = str(desired_value)

    if current_val != desired_value:
        if not module.check_mode:
            current['value'] = desired_value
            client.update_setting(setting_id, current)

        result['changed'] = True
        result['msg'] = f"Setting {setting_id} updated."
        # Return diff for Ansible to show changes
        if module._diff:
            result['diff'] = dict(before=str(current_val), after=str(desired_value))

    module.exit_json(**result)

if __name__ == '__main__':
    run_module()
