#!/usr/bin/python
""" PN CLI cpu-mgmt-class-modify """
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
module: pn_cpu_mgmt_class
author: "Pluribus Networks (devops@pluribusnetworks.com)"
version: 2
short_description: CLI command to modify cpu-mgmt-class.
description:
  - C(modify): Update mgmt port ingress policers
options:
  pn_action:
    description:
      - cpu-mgmt-class configuration command.
    required: true
    choices: ['modify']
    type: str
  pn_burst_size:
    description:
      - ingress traffic burst size (bytes) or default
    required: false
    type: str
  pn_name:
    description:
      - mgmt port ingress traffic class
    required: false
    choices: ['arp', 'icmp', 'ssh', 'snmp', 'fabric', 'bcast', 'nfs', 'web', 'web-ssl', 'net-api']
  pn_rate_limit:
    description:
      - ingress rate limit on mgmt port(bps) or unlimited
    required: false
    type: str
"""

EXAMPLES = """
- name: Modify cpu mgmt class
  pn_cpu_mgmt_class:
    pn_action: 'modify'
    pn_name: 'arp'
    pn_rate_limit: '1000'
    
- name: Modify cpu mgmt class
  pn_cpu_mgmt_class:
    pn_action: 'modify'
    pn_name: 'snmp'
    pn_rate_limit: '1000'
"""

RETURN = """
command:
  description: the CLI command run on the target node.
stdout:
  description: set of responses from the cpu-mgmt-class command.
  returned: always
  type: list
stderr:
  description: set of error responses from the cpu-mgmt-class command.
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
            msg="cpu-mgmt-class %s operation failed" % action,
            changed=False
        )

    if out:
        module.exit_json(
            command=' '.join(cli),
            stdout=out.strip(),
            msg="cpu-mgmt-class %s operation completed" % action,
            changed=True
        )

    else:
        module.exit_json(
            command=' '.join(cli),
            msg="cpu-mgmt-class %s operation completed" % action,
            changed=True
        )


def main():
    """ This section is for arguments parsing """
    module = AnsibleModule(
        argument_spec=dict(
            pn_action=dict(required=True, type='str', choices=['modify']),
            pn_burst_size=dict(required=False, type='str'),
            pn_name=dict(required=False, type='str', choices=['arp', 'icmp', \
                         'ssh', 'snmp', 'fabric', 'bcast', 'nfs', \
                         'web', 'web-ssl', 'net-api']),
            pn_rate_limit=dict(required=False, type='str'),
        )
    )

    # Accessing the arguments
    mod_action = module.params['pn_action']
    burst_size = module.params['pn_burst_size']
    name = module.params['pn_name']
    rate_limit = module.params['pn_rate_limit']

    # Building the CLI command string
    cli = pn_cli(module)
    cli += 'cpu-mgmt-class-' + mod_action
    if mod_action in ['modify']:
        if burst_size:
            cli += ' burst-size ' + burst_size
        if name:
            cli += ' name ' + name
        if rate_limit:
            cli += ' rate-limit ' + rate_limit

    run_cli(module, cli)

if __name__ == '__main__':
    main()
