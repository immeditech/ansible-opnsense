#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (C) 2026, Samuel Pulfer <samuel.pulfer@immeditech.ch>
# GNU General Public License v3.0+ (see https://www.gnu.org/licenses/gpl-3.0.txt)

# see: https://docs.opnsense.org/development/api/core/firewall.html

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.oxlorg.opnsense.plugins.module_utils.base.handler import \
    module_dependency_error, MODULE_EXCEPTIONS

try:
    from ansible_collections.oxlorg.opnsense.plugins.module_utils.base.wrapper import \
        module_wrapper
    from ansible_collections.oxlorg.opnsense.plugins.module_utils.defaults.main import \
        OPN_MOD_ARGS, STATE_MOD_ARG
    from ansible_collections.oxlorg.opnsense.plugins.module_utils.main.category import \
        Category

except MODULE_EXCEPTIONS:
    module_dependency_error()


# DOCUMENTATION = 'https://ansible-opnsense.oxl.app/firewall/category.html'
# EXAMPLES = 'https://ansible-opnsense.oxl.app/firewall/category.html'


def run_module():
    module_args = dict(
        name=dict(type='str', required=True, aliases=['n']),
        auto=dict(
            type='bool', required=False, default=False,
            description='Automatically removed when no longer referenced.'
        ),
        color=dict(
            type='str', required=False, default='',
            description='Hex color (RRGGBB) for visual distinction in the WebGUI.'
        ),
        **STATE_MOD_ARG,
        **OPN_MOD_ARGS,
    )

    result = dict(
        changed=False,
        diff={
            'before': {},
            'after': {},
        },
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True,
    )

    module_wrapper(Category(module=module, result=result))
    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
