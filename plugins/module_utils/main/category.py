from ansible.module_utils.basic import AnsibleModule

from ansible_collections.oxlorg.opnsense.plugins.module_utils.base.api import \
    Session
from ansible_collections.oxlorg.opnsense.plugins.module_utils.helper.main import \
    is_unset
from ansible_collections.oxlorg.opnsense.plugins.module_utils.helper.validate import \
    validate_str_fields
from ansible_collections.oxlorg.opnsense.plugins.module_utils.base.module import BaseModule


class Category(BaseModule):
    FIELD_ID = 'name'
    CMDS = {
        'add': 'add_item',
        'del': 'del_item',
        'set': 'set_item',
        'search': 'get',
        'toggle': 'toggleItem',
    }
    API_KEY_PATH = 'category.categories.category'
    API_MOD = 'firewall'
    API_CONT = 'category'
    FIELDS_CHANGE = ['auto', 'color']
    FIELDS_ALL = ['name']
    FIELDS_ALL.extend(FIELDS_CHANGE)
    FIELDS_TYPING = {
        'bool': ['auto'],
    }
    STR_VALIDATIONS = {
        'color': r'^[0-9a-fA-F]{6,6}$'
    }
    EXIST_ATTR = 'category'

    def __init__(self, module: AnsibleModule, result: dict, session: Session = None):
        BaseModule.__init__(self=self, m=module, r=result, s=session)
        self.category = {}

    def check(self) -> None:
        if not is_unset(self.p['color']):
            validate_str_fields(module=self.m, data=self.p, field_regex=self.STR_VALIDATIONS)

        self._base_check()

    def reload(self) -> None:
        # categories take effect immediately; no reload needed
        pass
