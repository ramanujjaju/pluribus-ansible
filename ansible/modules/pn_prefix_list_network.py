#!/usr/bin/python
""" PN CLI prefix-list-network-add/remove """

# Copyright 2018 Pluribus Networks
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import shlex
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.pn_nvos import pn_cli

DOCUMENTATION = """
---
module: pn_prefix_list_network
author: "Pluribus Networks (devops@pluribusnetworks.com)"
version: 2
short_description: CLI command to add/remove prefix-list-network.
description:
  - C(add): Add network associated with access list
  - C(remove): Remove networks associated with access list
options:
  pn_cliswitch:
    description:
      - Target switch to run the CLI on.
    required: False
    type: str
  pn_action:
    description:
      - prefix-list-network configuration command.
    required: true
    choices: ['add', 'remove']
    type: str
  pn_netmask:
    description:
      - netmask of the network associated the prefix list
    required: false
    type: str
  pn_name:
    description:
      - Prefix List Name
    required: false
    type: str
  pn_network:
    description:
      - network associated with the prefix list
    required: false
    type: str
"""

EXAMPLES = """
- name: add network to prefix list
  pn_prefix_list_network:
    pn_action: 'add'
    pn_name: 'block_prefix'
    pn_network: '2001:1111:abcd:1234::'
    pn_netmask: '64'

- name: remove network from prefix list
  pn_prefix_list_network:
    pn_action: 'remove'
    pn_name: 'block_prefix'
    pn_network: '2001:1111:abcd:1234::'
    pn_netmask: '64' 
"""

RETURN = """
command:
  description: the CLI command run on the target node.
stdout:
  description: set of responses from the prefix-list-network command.
  returned: always
  type: list
stderr:
  description: set of error responses from the prefix-list-network command.
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
            msg="prefix-list-network %s operation failed" % action,
            changed=False
        )

    if out:
        module.exit_json(
            command=' '.join(cli),
            stdout=out.strip(),
            msg="prefix-list-network %s operation completed" % action,
            changed=True
        )

    else:
        module.exit_json(
            command=' '.join(cli),
            msg="prefix-list-network %s operation completed" % action,
            changed=True
        )


def main():
    """ This section is for arguments parsing """
    module = AnsibleModule(
        argument_spec=dict(
            pn_cliswitch=dict(required=False, type='str'),
            pn_action=dict(required=True, type='str',
                        choices=['add', 'remove']),
            pn_netmask=dict(required=False, type='str'),
            pn_name=dict(required=False, type='str'),
            pn_network=dict(required=False, type='str'),
        )
    )

    # Accessing the arguments
    action = module.params['pn_action']
    netmask = module.params['pn_netmask']
    name = module.params['pn_name']
    network = module.params['pn_network']

    # Building the CLI command string
    cli = pn_cli(module)
    cli += 'prefix-list-network-' + action

    if name:
        cli += ' name ' + name
    if netmask:
        cli += ' netmask ' + netmask
    if network:
        cli += ' network ' + network
    
    run_cli(module, cli)

if __name__ == '__main__':
    main()
