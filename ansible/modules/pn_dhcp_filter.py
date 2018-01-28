#!/usr/bin/python
""" PN CLI dhcp-filter-create/modify/delete """

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
module: pn_dhcp_filter
author: "Pluribus Networks (devops@pluribusnetworks.com)"
version: 2
short_description: CLI command to create/modify/delete dhcp-filter.
description:
  - C(create): creates a new DHCP filter config
  - C(modify): modify a DHCP filter config
  - C(delete): deletes a DHCP filter config
options:
  pn_cliswitch:
    description:
      - Target switch to run the CLI on.
    required: False
    type: str
  pn_action:
    description:
      - dhcp-filter configuration command.
    required: true
    choices: ['create', 'modify', 'delete']
    type: str
  pn_trusted_ports:
    description:
      - trusted ports
    required: false
    type: str
  pn_name:
    description:
      - name of the DHCP filter
    required: false
    type: str
"""

EXAMPLES = """
- name: create DHCP filter
  pn_dhcp_filter:
    pn_action: 'create'
    pn_name: 'dhcp_filter'
    pn_trusted_ports: '10,11'

- name: delete DHCP filter
  pn_dhcp_filter:
    pn_action: 'delete'
    pn_name: 'dhcp_filter'
"""

RETURN = """
command:
  description: the CLI command run on the target node.
stdout:
  description: set of responses from the dhcp-filter command.
  returned: always
  type: list
stderr:
  description: set of error responses from the dhcp-filter command.
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
            msg="dhcp-filter %s operation failed" % action,
            changed=False
        )

    if out:
        module.exit_json(
            command=' '.join(cli),
            stdout=out.strip(),
            msg="dhcp-filter %s operation completed" % action,
            changed=True
        )

    else:
        module.exit_json(
            command=' '.join(cli),
            msg="dhcp-filter %s operation completed" % action,
            changed=True
        )


def main():
    """ This section is for arguments parsing """
    module = AnsibleModule(
        argument_spec=dict(
            pn_cliswitch=dict(required=False, type='str'),
            pn_action=dict(required=True, type='str',
                           choices=['create', 'modify', 'delete']),
            pn_trusted_ports=dict(required=False, type='str'),
            pn_name=dict(required=False, type='str'),
        )
    )

    # Accessing the arguments
    action = module.params['pn_action']
    trusted_ports = module.params['pn_trusted_ports']
    name = module.params['pn_name']

    # Building the CLI command string
    cli = pn_cli(module)
    cli += 'dhcp-filter-' + action
    cli += ' name ' + name

    if action in ['create', 'modify']:
        if trusted_ports:
            cli += ' trusted-ports ' + trusted_ports

    run_cli(module, cli)

if __name__ == '__main__':
    main()
