#!/usr/bin/python
""" PN CLI snmp-vacm-create/modify/delete """
#
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.
#

import shlex
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.pn_nvos import pn_cli

DOCUMENTATION = """
---
module: pn_snmp_vacm
author: "Pluribus Networks (devops@pluribusnetworks.com)"
version: 2
short_description: CLI command to create/modify/delete snmp-vacm.
description:
  - C(create): create View Access Control Models (VACM)
  - C(modify): modify View Access Control Models (VACM)
  - C(delete): delete View Access Control Models (VACM)
options:
  pn_cliswitch:
    description:
      - Target switch to run the CLI on.
    required: False
    type: str
  pn_action:
    description:
      - snmp-vacm configuration command.
    required: true
    choices: ['create', 'modify', 'delete']
    type: str
  pn_oid_restrict:
    description:
      - restrict OID
    required: false
    type: str
  pn_priv:
    description:
      - privileges
    required: false
    type: bool
  pn_auth:
    description:
      - authentication required
    required: false
    type: bool
  pn_user_type:
    description:
      - SNMP user type
    required: false
    choices: ['rouser', 'rwuser']
  pn_user_name:
    description:
      - SNMP administrator name
    required: false
    type: str
"""

EXAMPLES = """
- name: snmp vacm functionality
  pn_snmp_vacm:
    pn_action: "create"
    pn_user_name: "VINETrw"
    pn_auth: True
    pn_priv: True
    pn_user_type: "rwuser"
"""

RETURN = """
command:
  description: the CLI command run on the target node.
stdout:
  description: set of responses from the snmp-vacm command.
  returned: always
  type: list
stderr:
  description: set of error responses from the snmp-vacm command.
  returned: on error
  type: list
changed:
  description: indicates whether the CLI caused changes on the target.
  returned: always
  type: bool
"""


def run_cli(module, cli):
    """
    This method executes the cli command on the target node(s) and returns the
    output. The module then exits based on the output.
    :param cli: the complete cli string to be executed on the target node(s).
    :param module: The Ansible module to fetch command
    """
    action = module.params['pn_action']
    cli = shlex.split(cli)
    rc, out, err = module.run_command(cli)

    # Response in JSON format
    if err:
        module.exit_json(
            command=' '.join(cli),
            stderr=err.strip(),
            msg="snmp-vacm %s operation failed" % action,
            changed=False
        )

    if out:
        module.exit_json(
            command=' '.join(cli),
            stdout=out.strip(),
            msg="snmp-vacm %s operation completed" % action,
            changed=True
        )

    else:
        module.exit_json(
            command=' '.join(cli),
            msg="snmp-vacm %s operation completed" % action,
            changed=True
        )


def main():
    """ This section is for arguments parsing """
    module = AnsibleModule(
        argument_spec=dict(
            pn_cliswitch=dict(required=False, type='str'),
            pn_action=dict(required=True, type='str',
                        choices=['create', 'modify', 'delete']),
            pn_oid_restrict=dict(required=False, type='str'),
            pn_priv=dict(required=False, type='bool'),
            pn_auth=dict(required=False, type='bool'),
            pn_user_type=dict(required=False, type='str',
                              choices=['rouser', 'rwuser']),
            pn_user_name=dict(required=False, type='str'),
        )
    )

    # Accessing the arguments
    switch = module.params['pn_cliswitch']
    mod_action = module.params['pn_action']
    oid_restrict = module.params['pn_oid_restrict']
    priv = module.params['pn_priv']
    auth = module.params['pn_auth']
    user_type = module.params['pn_user_type']
    user_name = module.params['pn_user_name']

    # Building the CLI command string
    cli = pn_cli(module, switch)
    cli += ' snmp-vacm-' + mod_action
    if mod_action in ['create', 'modify']:
        if oid_restrict:
            cli += ' oid-restrict ' + oid_restrict
        if priv:
            if priv is True:
                cli += ' priv '
            else:
                cli += ' no-priv '
        if auth:
            if auth is True:
                cli += ' auth '
            else:
                cli += ' no-auth '
        if user_type:
            cli += ' user-type ' + user_type

    if mod_action in ['create', 'delete', 'modify']:
        if user_name:
            cli += ' user-name ' + user_name

    run_cli(module, cli)

if __name__ == '__main__':
    main()
