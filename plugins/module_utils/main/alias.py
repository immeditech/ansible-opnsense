from ansible.module_utils.basic import AnsibleModule

from ansible_collections.oxlorg.opnsense.plugins.module_utils.base.handler import \
    ModuleSoftError
from ansible_collections.oxlorg.opnsense.plugins.module_utils.base.api import \
    Session
from ansible_collections.oxlorg.opnsense.plugins.module_utils.helper.alias import \
    validate_values, filter_builtin_alias, build_updatefreq
from ansible_collections.oxlorg.opnsense.plugins.module_utils.helper.category import \
    resolve_categories
from ansible_collections.oxlorg.opnsense.plugins.module_utils.helper.main import \
    get_simple_existing, simplify_translate, is_unset
from ansible_collections.oxlorg.opnsense.plugins.module_utils.base.cls import BaseModule


class Alias(BaseModule):
    FIELD_ID = 'name'
    CMDS = {
        'add': 'add_item',
        'del': 'del_item',
        'set': 'set_item',
        'search': 'get',
        'toggle': 'toggleItem',
    }
    API_KEY_PATH = 'alias.aliases.alias'
    API_MOD = 'firewall'
    API_CONT = 'alias'
    FIELDS_CHANGE = ['content', 'description', 'categories']
    FIELDS_ALL = ['name', 'type', 'enabled']
    FIELDS_ALL.extend(FIELDS_CHANGE)
    FIELDS_ALL.extend(['updatefreq_days', 'interface', 'path_expression'])
    FIELDS_TRANSLATE = {
        'updatefreq_days': 'updatefreq',
    }
    FIELDS_TYPING = {
        'bool': ['enabled'],
        'select': ['type', 'interface'],
        # `categories` arrives from firewall.alias.get as a dict-of-dicts with
        # per-entry {'selected': 0|1}; type 'list' funnels it through
        # get_selected_list(get_value=False) → returns the list of selected
        # category UUIDs, which is what we compare against (user input is
        # resolved to UUIDs before this comparison via resolve_categories()).
        'list': ['categories'],
    }
    EXIST_ATTR = 'alias'
    JOIN_CHAR = '\n'
    TIMEOUT = 20.0
    MAX_ALIAS_LEN = 32

    def __init__(
            self, module: AnsibleModule, result: dict, multi: dict = None,
            session: Session = None, fail: dict = None,
    ):
        BaseModule.__init__(self=self, m=module, r=result, s=session, f=fail, multi=multi)
        self.alias = {}

    def check(self) -> None:
        if self.p['type'] == 'urltable':
            self.FIELDS_CHANGE = self.FIELDS_CHANGE + ['updatefreq_days']
            self.p['updatefreq_days'] = build_updatefreq(self.p['updatefreq_days'], default=True)

        elif self.p['type'] == 'urljson':
            self.FIELDS_CHANGE = self.FIELDS_CHANGE + ['updatefreq_days', 'path_expression']
            self.p['updatefreq_days'] = build_updatefreq(self.p['updatefreq_days'], default=True)

        elif self.p['type'] == 'dynipv6host':
            if is_unset(self.p['interface']):
                self.m.fail_json('You need to provide an interface to create a dynipv6host alias!')

            self.FIELDS_CHANGE = self.FIELDS_CHANGE + ['interface']

        if len(self.p['name']) > self.MAX_ALIAS_LEN:
            self._error(
                f"Alias name '{self.p['name']}' is invalid - "
                f"must be shorter than {self.MAX_ALIAS_LEN} characters",
            )

        if self.p['state'] == 'present' and not is_unset(self.p.get('categories', [])):
            resolve_categories(self, self.p)

        self.b.find(match_fields=[self.FIELD_ID])

        if self.p['state'] == 'present':
            validate_values(error_func=self._error, cnf=self.p, existing_entries=self.existing_entries)

        self._base_check()

    def simplify_existing(self, alias: dict) -> dict:
        simple = {}

        if isinstance(alias['content'], dict):
            simple['content'] = [item for item in alias['content'].keys() if item != '']

        else:
            # if function is re-applied
            return alias

        simple = {
            **simplify_translate(
                existing=alias,
                typing=self.FIELDS_TYPING,
                translate=self.FIELDS_TRANSLATE,
            ),
            **simple,
        }

        if simple['type'] in ['urltable', 'urljson']:
            simple['updatefreq_days'] = build_updatefreq(alias['updatefreq'], default=False)

        return simple

    def update(self) -> None:
        # checking if alias changed
        if self.alias['type'] == self.p['type']:
            self.b.update()

        else:
            self.r['changed'] = True
            self._error(
                msg=f"Unable to update alias '{self.p[self.FIELD_ID]}' - it is not of the same type! "
                    f"You need to delete the current one first!",
                verification=False,
            )

    def delete(self) -> None:
        response = self.b.delete()

        if 'in_use' in response:
            self._error(
                msg=f"Unable to delete alias '{self.p[self.FIELD_ID]}' as it is currently referenced!",
                verification=False,
            )

    def _error(self, msg: str, verification: bool = True) -> None:
        if (verification and self.fail_verify) or (not verification and self.fail_process):
            self.m.fail_json(msg)

        else:
            self.m.warn(msg)
            raise ModuleSoftError

    def get_existing(self) -> list:
        return filter_builtin_alias(
            get_simple_existing(
                entries=self.b.search(),
                simplify_func=self.simplify_existing,
            )
        )

    def _build_request(self) -> dict:
        # JOIN_CHAR for the alias module is '\n' (used to glue together
        # content entries on the wire). OPNsense expects categories as a
        # comma-separated list of UUIDs in the same payload — so we
        # materialise that string here, then let the generic build_request
        # pass it through unchanged (string, not list → no further join).
        saved = self.p.get('categories')
        if isinstance(saved, list):
            self.p['categories'] = ','.join(saved) if saved else ''
        try:
            return self.b.build_request()
        finally:
            # Restore the list so subsequent diff/log code does not see the
            # string (it would render badly in --diff output).
            if isinstance(saved, list):
                self.p['categories'] = saved
