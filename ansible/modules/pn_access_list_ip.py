#!/usr/bin/python
""" PN CLI access-list-ip-add/remove """

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
module: pn_access_list_ip
author: "Pluribus Networks (devops@pluribusnetworks.com)"
version: 2
short_description: CLI command to add/remove access-list-ip.
description:
  - C(add): Add IPs associated with access list
  - C(remove): Remove IPs associated with access list
options:
  pn_cliswitch:
    description:
      - Target switch to run the CLI on.
    required: False
    type: str
  pn_action:
    description:
      - access-list-ip configuration command.
    required: true
    choices: ['add', 'remove']
    type: str
  pn_ip:
    description:
      - IP associated with the access list
    required: false
    type: str
  pn_name:
    description:
      - Access List Name
    required: false
    type: str
"""

EXAMPLES = """
- name: add ip to access list
  pn_access_list_ip:
    pn_action: 'add'
    pn_name: 'block_src'
    pn_ip: 'fe80::640e:94ff:fe27:5f0f'

- name: remove ip from access list
  pn_access_list_ip:
    pn_action: 'remove'
    pn_name: 'block_src'
    pn_ip: 'fe80::640e:94ff:fe27:5f0f'
"""

RETURN = """
command:
  description: the CLI command run on the target node.
stdout:
  description: set of responses from the access-list-ip command.
  returned: always
  type: list
stderr:
  description: set of error responses from the access-list-ip command.
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
            msg="access-list-ip %s operation failed" % action,
            changed=False
        )

    if out:
        module.exit_json(
            command=' '.join(cli),
            stdout=out.strip(),
            msg="access-list-ip %s operation completed" % action,
            changed=True
        )

    else:
        module.exit_json(
            command=' '.join(cli),
            msg="access-list-ip %s operation completed" % action,
            changed=True
        )


def main():
    """ This section is for arguments parsing """
    module = AnsibleModule(
        argument_spec=dict(
            pn_cliswitch=dict(required=False, type='str'),
            pn_action=dict(required=True, type='str',
                           choices=['add', 'remove']),
            pn_ip=dict(required=False, type='str'),
            pn_name=dict(required=False, type='str'),
        )
    )

    # Accessing the arguments
    action = module.params['pn_action']
    ip = module.params['pn_ip']
    name = module.params['pn_name']

    # Building the CLI command string
    cli = pn_cli(module)
    cli += 'access-list-ip-' + action
    if ip:
        cli += ' ip ' + ip
    if name:
        cli += ' name ' + name
    
    run_cli(module, cli)

if __name__ == '__main__':
    main()
