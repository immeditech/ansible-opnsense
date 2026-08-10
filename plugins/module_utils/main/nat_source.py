from ansible.module_utils.basic import AnsibleModule

from ansible_collections.oxlorg.opnsense.plugins.module_utils.base.api import \
    Session
from ansible_collections.oxlorg.opnsense.plugins.module_utils.helper.validate import \
    is_unset
from ansible_collections.oxlorg.opnsense.plugins.module_utils.helper.rule import \
    validate_values
from ansible_collections.oxlorg.opnsense.plugins.module_utils.helper.category import \
    resolve_categories
from ansible_collections.oxlorg.opnsense.plugins.module_utils.base.module import BaseModule


class SNat(BaseModule):
    CMDS = {
        'add': 'add_rule',
        'del': 'del_rule',
        'set': 'set_rule',
        'search': 'get',
        'toggle': 'toggle_rule',
    }
    API_KEY_PATH = 'filter.snatrules.rule'
    API_MOD = 'firewall'
    API_CONT = 'source_nat'
    # OPNsense 26.7 no longer returns the snat rules from
    # 'firewall/source_nat/get' (only the 'general' snat_mode section) —
    # fetch them from the full 'firewall/filter/get' tree instead, which
    # still carries 'filter.snatrules.rule'. Write commands (add_rule etc.)
    # stay on the 'source_nat' controller.
    API_CONT_GET = 'filter'
    FIELDS_CHANGE = [
        'sequence', 'no_nat', 'interface', 'target', 'target_port', 'description',
        'ip_protocol', 'protocol', 'source_invert', 'source_net', 'source_port',
        'destination_invert', 'destination_net', 'destination_port', 'log', 'static_port',
        'categories',
    ]
    FIELDS_ALL = ['enabled']
    FIELDS_ALL.extend(FIELDS_CHANGE)
    FIELDS_TRANSLATE = {
        'ip_protocol': 'ipprotocol',
        'source_invert': 'source_not',
        'destination_invert': 'destination_not',
        'no_nat': 'nonat',
        'static_port': 'staticnatport',
    }
    FIELDS_TYPING = {
        'bool': ['enabled', 'log', 'source_invert', 'no_nat', 'destination_invert', 'static_port'],
        'list': ['categories'],
        'select': ['interface', 'ip_protocol', 'protocol'],
        'int': [],
    }
    INT_VALIDATIONS = {
        'sequence': {'min': 1, 'max': 99999},
    }
    EXIST_ATTR = 'rule'
    API_CMD_REL = 'apply'

    def __init__(
            self, module: AnsibleModule, result: dict, multi: dict = None,
            session: Session = None, fail: dict = None,
    ):
        BaseModule.__init__(self=self, m=module, r=result, s=session, f=fail, multi=multi)
        self.rule = {}

    def check(self) -> None:
        if self.p['state'] == 'present':
            if is_unset(self.p['interface']):
                self.m.fail_json(
                    "You need to provide an 'interface' to create a source-nat rule!"
                )

            if is_unset(self.p['target']):
                self.m.fail_json(
                    "You need to provide an 'target' to create a source-nat rule!"
                )

        self._build_log_name()

        if self.p['state'] == 'present' and not is_unset(self.p.get('categories', [])):
            resolve_categories(self, self.p)

        self.find(match_fields=self.p['match_fields'])

        if self.p['state'] == 'present':
            validate_values(module=self.m, cnf=self.p, error_func=self.m.fail_json, kind='nat')

        self._base_check()

    def _build_log_name(self) -> str:
        if self.p['description'] not in [None, '']:
            log_name = self.p['description']

        else:
            log_name = 'FROM '

            if self.p['source_invert']:
                log_name += 'NOT '

            log_name += f"{self.p['source_net']} <= PROTO {self.p['protocol']} => "

            if self.p['destination_invert']:
                log_name += 'NOT '

            log_name += f"{self.p['destination_net']}:{self.p['destination_port']} "
            log_name += f" =NAT=> {self.p['target']}:{self.p['target_port']}"

        return log_name
