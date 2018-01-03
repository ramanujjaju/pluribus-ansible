#!/usr/bin/python
""" PN CLI vrouter-pim-config-modify """
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
module: pn_vrouter_pim_config
author: "Pluribus Networks (devops@pluribusnetworks.com)"
version: 2
short_description: CLI command to modify vrouter-pim-config.
description:
  - C(modify): modify pim parameters
options:
  pn_cliswitch:
    description:
      - Target switch to run the CLI on.
    required: False
    type: str
  action:
    description:
      - vrouter-pim-config configuration command.
    required: true
    choices: ['modify']
    type: str
  pn_query_interval:
    description:
      - igmp query interval in seconds
    required: false
    type: str
  pn_querier_timeout:
    description:
      - igmp querier timeout in seconds
    required: false
    type: str
  pn_hello_interval:
    description:
      - hello interval in seconds
    required: false
    type: str
  pn_vrouter_name:
    description:
      - name of service config
    required: false
    type: str
"""

EXAMPLES = """
- name: Modify pim config
  pn_vrouter_pim_config:
    pn_cliswitch: "{{ inventory_hostname }}"
    pn_query_interval: "10"
    pn_querier_timeout: "30"
"""

RETURN = """
command:
  description: the CLI command run on the target node.
stdout:
  description: set of responses from the vrouter-pim-config command.
  returned: always
  type: list
stderr:
  description: set of error responses from the vrouter-pim-config command.
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
    action = module.params['action']
    cli = shlex.split(cli)
    rc, out, err = module.run_command(cli)

    # Response in JSON format
    if err:
        module.fail_json(
            command=' '.join(cli),
            stderr=err.strip(),
            msg="vrouter-pim-config %s operation failed" % action,
            changed=False
        )

    if out:
        module.exit_json(
            command=' '.join(cli),
            stdout=out.strip(),
            msg="vrouter-pim-config %s operation completed" % action,
            changed=True
        )

    else:
        module.exit_json(
            command=' '.join(cli),
            msg="vrouter-pim-config %s operation completed" % action,
            changed=True
        )


def main():
    """ This section is for arguments parsing """
    module = AnsibleModule(
        argument_spec=dict(
            pn_cliswitch=dict(required=False, type='str'),
            action=dict(required=True, type='str', choices=['modify']),
            pn_query_interval=dict(required=False, type='str'),
            pn_querier_timeout=dict(required=False, type='str'),
            pn_hello_interval=dict(required=False, type='str'),
            pn_vrouter_name=dict(required=False, type='str'),
        )
    )

    # Accessing the arguments
    mod_action = module.params['action']
    query_interval = module.params['pn_query_interval']
    querier_timeout = module.params['pn_querier_timeout']
    hello_interval = module.params['pn_hello_interval']
    vrouter_name = module.params['pn_cliswitch'] + '-vrouter'

    # Building the CLI command string
    cli = pn_cli(module)
    cli += ' vrouter-pim-config-' + mod_action
    if mod_action in ['modify']:
        if query_interval:
            cli += ' query-interval ' + query_interval
        if querier_timeout:
            cli += ' querier-timeout ' + querier_timeout
        if hello_interval:
            cli += ' hello-interval ' + hello_interval
        if vrouter_name:
            cli += ' vrouter-name ' + vrouter_name
    run_cli(module, cli)

if __name__ == '__main__':
    main()
