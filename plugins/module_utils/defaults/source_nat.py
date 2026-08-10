from ansible_collections.oxlorg.opnsense.plugins.module_utils.defaults.main import \
    STATE_MOD_ARG
from ansible_collections.oxlorg.opnsense.plugins.module_utils.defaults.rule import \
    RULE_MOD_ARGS

SNAT_MATCH_FIELDS_ARG = dict(
    match_fields=dict(
        type='list', required=True, elements='str',
        description='Fields that are used to match configured rules with the running config - '
                    "if any of those fields are changed, the module will think it's a new rule",
        choices=[
            'sequence', 'interface', 'target', 'target_port', 'ip_protocol', 'protocol',
            'source_invert', 'source_net', 'source_port', 'destination_invert', 'destination_net',
            'destination_port', 'description', 'uuid', 'static_port',
        ]
    ),
)

SNAT_MOD_ARGS = dict(
    no_nat=dict(
        type='bool', required=False, default=False,
        description='Enabling this option will disable NAT for traffic matching '
                    'this rule and stop processing Outbound NAT rules.'
    ),
    interface=dict(type='str', required=False, aliases=['int', 'i']),
    target=dict(
        type='str', required=False, aliases=['tgt', 't'],
        description='NAT translation target - Packets matching this rule will be '
                    'mapped to the IP address given here.',
    ),
    target_port=dict(type='int', required=False, aliases=['nat_port', 'np']),
    static_port=dict(
        type='bool', required=False, default=False,
        aliases=['staticnatport', 'static_nat_port'],
        description='Preserve the source port instead of randomizing it. '
                    'Required for protocols that embed the source port in '
                    'their payload (e.g. some game consoles needing NAT '
                    'type B/Open).'
    ),
    sequence=RULE_MOD_ARGS['sequence'],
    ip_protocol=RULE_MOD_ARGS['ip_protocol'],
    protocol=RULE_MOD_ARGS['protocol'],
    source_invert=RULE_MOD_ARGS['source_invert'],
    source_net=RULE_MOD_ARGS['source_net'],
    source_port=RULE_MOD_ARGS['source_port'],
    destination_invert=RULE_MOD_ARGS['destination_invert'],
    destination_net=RULE_MOD_ARGS['destination_net'],
    destination_port=RULE_MOD_ARGS['destination_port'],
    log=RULE_MOD_ARGS['log'],
    uuid=RULE_MOD_ARGS['uuid'],
    description=RULE_MOD_ARGS['description'],
    categories=RULE_MOD_ARGS['categories'],
    **STATE_MOD_ARG,
    **SNAT_MATCH_FIELDS_ARG,
)
