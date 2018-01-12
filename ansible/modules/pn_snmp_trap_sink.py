#!/usr/bin/python
""" PN CLI snmp-trap-sink-create/delete """
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
module: pn_snmp_trap_sink
author: "Pluribus Networks (devops@pluribusnetworks.com)"
version: 2
short_description: CLI command to create/delete snmp-trap-sink.
description:
  - C(create): create a SNMPv1 trap receiver
  - C(delete): delete a SNMPv1 trap receiver
options:
  pn_cliswitch:
    description:
      - Target switch to run the CLI on.
    required: False
    type: str
  pn_action:
    description:
      - snmp-trap-sink configuration command.
    required: true
    choices: ['create', 'delete']
    type: str
  pn_dest_host:
    description:
      - destination host
    required: false
    type: str
  pn_community:
    description:
      - community type
    required: false
    type: str
  pn_dest_port:
    description:
      - destination port - default 162
    required: false
    type: str
  pn_type:
    description:
      - trap type - default TRAP_TYPE_V2C_TRAP
    required: false
    choices: ['TRAP_TYPE_V1_TRAP', 'TRAP_TYPE_V2C_TRAP', 'TRAP_TYPE_V2_INFORM']
"""

EXAMPLES = """
- name: snmp trap sink functionality
  pn_snmp_trap_sink:
    pn_action: "create"
    pn_cliswitch: "{{ inventory_hostname }}"
    pn_community: "baseball"
    pn_type: "TRAP_TYPE_V2_INFORM"
    pn_dest_host: "104.254.40.101"
"""

RETURN = """
command:
  description: the CLI command run on the target node.
stdout:
  description: set of responses from the snmp-trap-sink command.
  returned: always
  type: list
stderr:
  description: set of error responses from the snmp-trap-sink command.
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
        module.fail_json(
            command=' '.join(cli),
            stderr=err.strip(),
            msg="snmp-trap-sink %s operation failed" % action,
            changed=False
        )

    if out:
        module.exit_json(
            command=' '.join(cli),
            stdout=out.strip(),
            msg="snmp-trap-sink %s operation completed" % action,
            changed=True
        )

    else:
        module.exit_json(
            command=' '.join(cli),
            msg="snmp-trap-sink %s operation completed" % action,
            changed=True
        )


def main():
    """ This section is for arguments parsing """
    module = AnsibleModule(
        argument_spec=dict(
            pn_cliswitch=dict(required=False, type='str'),
            pn_action=dict(required=True, type='str',
                           choices=['create', 'delete']),
            pn_dest_host=dict(required=False, type='str'),
            pn_community=dict(required=False, type='str'),
            pn_dest_port=dict(required=False, type='str'),
            pn_type=dict(required=False, type='str',
                         choices=['TRAP_TYPE_V1_TRAP',
                         'TRAP_TYPE_V2C_TRAP', 'TRAP_TYPE_V2_INFORM']),
        )
    )

    # Accessing the arguments
    switch = module.params['pn_cliswitch']
    mod_action = module.params['pn_action']
    dest_host = module.params['pn_dest_host']
    community = module.params['pn_community']
    dest_port = module.params['pn_dest_port']
    type = module.params['pn_type']

    # Building the CLI command string
    cli = pn_cli(module, switch)
    cli += ' snmp-trap-sink-' + mod_action
    if mod_action in ['create', 'delete']:
        if dest_host:
            cli += ' dest-host ' + dest_host
        if community:
            cli += ' community ' + community
        if dest_port:
            cli += ' dest-port ' + dest_port

    if mod_action in ['create']:
        if type:
            cli += ' type ' + type

    run_cli(module, cli)

if __name__ == '__main__':
    main()
