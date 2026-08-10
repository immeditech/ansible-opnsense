from ansible.module_utils.basic import AnsibleModule

from ansible_collections.oxlorg.opnsense.plugins.module_utils.base.handler import \
    ModuleSoftError
from ansible_collections.oxlorg.opnsense.plugins.module_utils.helper.validate import \
    validate_int_fields
from ansible_collections.oxlorg.opnsense.plugins.module_utils.base.api import Session
from ansible_collections.oxlorg.opnsense.plugins.module_utils.helper.rule import \
    validate_values
from ansible_collections.oxlorg.opnsense.plugins.module_utils.helper.category import \
    resolve_categories
from ansible_collections.oxlorg.opnsense.plugins.module_utils.helper.main import \
    is_unset
from ansible_collections.oxlorg.opnsense.plugins.module_utils.base.module import BaseModule


class Rule(BaseModule):
    MULTI_DIFF_KEY = 'description'
    CMDS = {
        'add': 'add_rule',
        'del': 'del_rule',
        'set': 'set_rule',
        'search': 'get',
        'toggle': 'toggle_rule',
    }
    API_KEY_PATH = 'filter.rules.rule'
    API_MOD = 'firewall'
    API_CONT = 'filter'
    FIELDS_CHANGE = [
        'sequence', 'action', 'quick', 'interface', 'interface_invert', 'direction',
        'ip_protocol', 'protocol', 'source_invert', 'source_net', 'source_port',
        'destination_invert', 'destination_net', 'destination_port', 'log',
        'tag', 'tagged', 'description', 'gateway', 'replyto', 'disable_replyto',
        'allow_opts', 'state_type', 'state_policy', 'state_timeout',
        'max_states', 'max_src_nodes', 'max_src_states', 'max_src_conn', 'max_src_conn_rate',
        'max_src_conn_rates', 'overload', 'adaptive_start', 'adaptive_end', 'prio', 'set_prio', 'set_prio_low',
        'tcp_flags', 'tcp_flags_clear', 'schedule', 'tos', 'icmp_type', 'icmpv6_type',
        'divert_to', 'shaper1', 'shaper2', 'categories',
    ]
    FIELDS_ALL = ['enabled']
    FIELDS_ALL.extend(FIELDS_CHANGE)
    FIELDS_TRANSLATE = {
        'interface_invert': 'interfacenot',
        'ip_protocol': 'ipprotocol',
        'source_invert': 'source_not',
        'destination_invert': 'destination_not',
        'disable_replyto': 'disablereplyto',
        'allow_opts': 'allowopts',
        'state_type': 'statetype',
        'state_policy': 'state-policy',
        'state_timeout': 'statetimeout',
        'max_states': 'max',
        'max_src_nodes': 'max-src-nodes',
        'max_src_states': 'max-src-states',
        'max_src_conn': 'max-src-conn',
        'max_src_conn_rate': 'max-src-conn-rate',
        'max_src_conn_rates': 'max-src-conn-rates',
        'adaptive_start': 'adaptivestart',
        'adaptive_end': 'adaptiveend',
        'set_prio': 'set-prio',
        'set_prio_low': 'set-prio-low',
        'tcp_flags': 'tcpflags1',
        'tcp_flags_clear': 'tcpflags2',
        'schedule': 'sched',
        'icmp_type': 'icmptype',
        'icmpv6_type': 'icmp6type',
        'divert_to': 'divert-to',
    }
    FIELDS_TYPING = {
        'bool': [
            'enabled', 'log', 'quick', 'interface_invert', 'source_invert', 'destination_invert', 'disable_replyto',
            'allow_opts',
        ],
        'select': [
            'action', 'direction', 'ip_protocol', 'protocol', 'gateway', 'replyto', 'state_type', 'state_policy',
            'overload', 'prio', 'set_prio', 'set_prio_low', 'schedule', 'tos',
            'divert_to', 'shaper1', 'shaper2',
        ],
        # `categories` arrives from firewall.filter.get as a dict-of-dicts with
        # per-entry {'selected': 0|1}; type 'list' funnels it through
        # get_selected_list(get_value=False) → list of selected category UUIDs
        # (user input is resolved to UUIDs beforehand via resolve_categories()).
        'list': ['interface', 'tcp_flags', 'tcp_flags_clear', 'icmp_type', 'icmpv6_type', 'categories'],
        'int': ['sequence', 'state_timeout'],
    }
    FIELDS_OPTIONAL = ['icmp_type', 'icmpv6_type']
    # OPNsense >= 26.7 keys the icmp6type select by numeric ICMPv6 type code;
    # map the module's symbolic names accordingly (list field, so the generic
    # whole-value FIELDS_VALUE_MAPPING cannot be used).
    ICMP6_TYPE_MAP = {
        'unreach': '1', 'toobig': '2', 'timex': '3', 'paramprob': '4',
        'echoreq': '128', 'echorep': '129', 'listqry': '130', 'listenrep': '131',
        'listendone': '132', 'routersol': '133', 'reouteradv': '134',
        'neighbrsol': '135', 'neighbradv': '136', 'redir': '137',
        'routrrenum': '138', 'niqry': '139', 'nirep': '140',
        'mtraceresp': '200', 'mtrace': '201',
    }
    EXIST_ATTR = 'rule'
    TIMEOUT = 60.0  # urltable etc reload
    INT_VALIDATIONS = {
        'sequence': {'min': 1, 'max': 99999},
        'state_timeout': {'min': 1},
    }
    API_CMD_REL = 'apply'

    def __init__(
            self, module: AnsibleModule, result: dict, multi: dict = None,
            session: Session = None, fail: dict = None,
    ):
        BaseModule.__init__(self=self, m=module, r=result, s=session, f=fail, multi=multi)
        self.rule = {}
        self.log_name = None

    def _build_log_name(self) -> str:
        if self.p['description'] not in [None, '']:
            log_name = self.p['description']

        else:
            log_name = f"{self.p['action'].upper()}: FROM "

            if self.p['source_invert']:
                log_name += 'NOT '

            log_name += f"{self.p['source_net']} <= PROTO {self.p['protocol']} => "

            if self.p['destination_invert']:
                log_name += 'NOT '

            log_name += f"{self.p['destination_net']}:{self.p['destination_port']}"

        return log_name

    def check(self) -> None:
        if self.p['state'] == 'present':
            validate_int_fields(
                module=self.m,
                data=self.p,
                field_minmax=self.INT_VALIDATIONS,
                error_func=self._error
            )

        self._build_log_name()

        if not is_unset(self.p.get('icmpv6_type', [])):
            self.p['icmpv6_type'] = [
                self.ICMP6_TYPE_MAP.get(t, t) for t in self.p['icmpv6_type']
            ]

        if self.p['state'] == 'present' and not is_unset(self.p.get('categories', [])):
            resolve_categories(self, self.p)

        self.find(match_fields=self.p['match_fields'])

        if self.p['state'] == 'present':
            validate_values(module=self.m, cnf=self.p, error_func=self._error)

        self._base_check()

    def _error(self, msg: str, verification: bool = True) -> None:
        if (verification and self.fail_verify) or (not verification and self.fail_process):
            self.m.fail_json(msg)

        else:
            self.m.warn(msg)
            raise ModuleSoftError
