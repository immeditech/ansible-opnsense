from ansible.module_utils.basic import AnsibleModule


def resolve_categories(module: AnsibleModule, params: dict) -> None:
    """
    Resolve a list of category names to their OPNsense UUIDs.

    The user provides categories by *name* in the playbook (intuitive,
    stable across reinstalls). OPNsense persists the relation as a
    comma-separated list of UUIDs, so we look up each name in the
    existing category set and replace it in `params['categories']` in place.

    Unknown names are passed through unchanged. If the user supplied
    a literal UUID, it matches no name and is also passed through —
    OPNsense will accept it directly.

    Idempotent across multiple calls per run thanks to caching on the
    module instance (`existing_categories`).
    """
    # Cache on the shared AnsibleModule (module.m) when called with a
    # BaseModule entry-instance: multi-modules (rule_multi, alias_multi)
    # create one entry-instance per item, so an instance-level cache would
    # re-fetch the category set for every single entry.
    cache_holder = getattr(module, 'm', module)

    if not hasattr(cache_holder, 'existing_categories'):
        categories = module.s.get(cnf={
            'module': 'firewall',
            'controller': 'category',
            'command': 'get',
        })

        cache_holder.existing_categories = {
            category['name']: uuid
            for uuid, category in
            categories['category']['categories']['category'].items()
        }

    if not isinstance(params['categories'], list):
        params['categories'] = [params['categories']]

    params['categories'] = [
        cache_holder.existing_categories.get(name, name)
        for name in params['categories']
    ]
