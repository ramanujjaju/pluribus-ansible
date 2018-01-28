#!/usr/bin/python
""" PN CLI prefix-list-create/delete """

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
module: pn_prefix_list
author: "Pluribus Networks (devops@pluribusnetworks.com)"
version: 2
short_description: CLI command to create/delete prefix-list.
description:
  - C(create): create a prefix list
  - C(delete): delete a prefix list
options:
  pn_cliswitch:
    description:
      - Target switch to run the CLI on.
    required: False
    type: str
  pn_action:
    description:
      - prefix-list configuration command.
    required: true
    choices: ['create', 'delete']
    type: str
  pn_name:
    description:
      - Prefix List Name
    required: false
    type: str
  pn_scope:
    description:
      - scope - local or fabric
    required: false
    choices: ['local', 'fabric']
"""

EXAMPLES = """
- name: create prefix list
  pn_prefix_list:
    pn_action: 'create'
    pn_name: 'block_prefix'
    pn_scope: 'local'

-name: delete prefix list
 pn_prefix_list:
   pn_action: 'delete'
   pn_name: 'block_prefix'
"""

RETURN = """
command:
  description: the CLI command run on the target node.
stdout:
  description: set of responses from the prefix-list command.
  returned: always
  type: list
stderr:
  description: set of error responses from the prefix-list command.
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
            msg="prefix-list %s operation failed" % action,
            changed=False
        )

    if out:
        module.exit_json(
            command=' '.join(cli),
            stdout=out.strip(),
            msg="prefix-list %s operation completed" % action,
            changed=True
        )

    else:
        module.exit_json(
            command=' '.join(cli),
            msg="prefix-list %s operation completed" % action,
            changed=True
        )


def main():
    """ This section is for arguments parsing """
    module = AnsibleModule(
        argument_spec=dict(
            pn_cliswitch=dict(required=False, type='str'),
            pn_action=dict(required=True, type='str',
                           choices=['create', 'delete']),
            pn_name=dict(required=False, type='str'),
            pn_scope=dict(required=False, type='str',
                          choices=['local', 'fabric']),
        )
    )

    # Accessing the arguments
    action = module.params['pn_action']
    name = module.params['pn_name']
    scope = module.params['pn_scope']

    # Building the CLI command string
    cli = pn_cli(module)
    cli += 'prefix-list-' + action

    if name:
        cli += ' name ' + name
    
    if action == 'create':
        if scope:
            cli += ' scope ' + scope
    
    run_cli(module, cli)

if __name__ == '__main__':
    main()
