#!/usr/bin/python
""" PN CLI cpu-class-create/modify/delete """
#
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
#

import shlex
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.pn_nvos import pn_cli

DOCUMENTATION = """
---
module: pn_cpu_class
author: "Pluribus Networks (devops@pluribusnetworks.com)"
version: 2
short_description: CLI command to create/modify/delete cpu-class.
description:
  - C(create): Add CPU class
  - C(modify): modify CPU class information
  - C(delete): delete a CPU class
options:
  pn_action:
    description:
      - cpu-class configuration command.
    required: true
    choices: ['create', 'modify', 'delete']
    type: str
  pn_scope:
    description:
      - scope for CPU class
    required: false
    choices: ['local', 'fabric']
  pn_hog_protect:
    description:
      - enable host-based hog protection
    required: false
    choices: ['disable', 'enable', 'enable-and-drop']
  pn_rate_limit:
    description:
      - rate-limit for CPU class
    required: false
    type: str
  pn_name:
    description:
      - name for the CPU class
    required: false
    type: str
"""

EXAMPLES = """
- name: Modify cpu class
  pn_cpu_class:
    pn_action: 'modify'
    pn_name: 'ospf'
    pn_hog_protect: 'enable'
"""

RETURN = """
command:
  description: the CLI command run on the target node.
stdout:
  description: set of responses from the cpu-class command.
  returned: always
  type: list
stderr:
  description: set of error responses from the cpu-class command.
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
            msg="cpu-class %s operation failed" % action,
            changed=False
        )

    if out:
        module.exit_json(
            command=' '.join(cli),
            stdout=out.strip(),
            msg="cpu-class %s operation completed" % action,
            changed=True
        )

    else:
        module.exit_json(
            command=' '.join(cli),
            msg="cpu-class %s operation completed" % action,
            changed=True
        )


def main():
    """ This section is for arguments parsing """
    module = AnsibleModule(
        argument_spec=dict(
            pn_cliswitch=dict(required=False, type='str'),
            pn_action=dict(required=True, type='str',
                        choices=['create', 'modify', 'delete']),
            pn_scope=dict(required=False, type='str',
                          choices=['local', 'fabric']),
            pn_hog_protect=dict(required=False, type='str',
                                choices=['disable', 'enable',
                                          'enable-and-drop']),
            pn_rate_limit=dict(required=False, type='str'),
            pn_name=dict(required=False, type='str'),
        )
    )

    # Accessing the arguments
    mod_action = module.params['pn_action']
    scope = module.params['pn_scope']
    hog_protect = module.params['pn_hog_protect']
    rate_limit = module.params['pn_rate_limit']
    name = module.params['pn_name']

    # Building the CLI command string
    cli = pn_cli(module)
    cli += ' cpu-class-' + mod_action
    if mod_action in ['create']:
        if scope:
            cli += ' scope ' + scope

    if mod_action in ['create', 'modify']:
        if hog_protect:
            cli += ' hog-protect ' + hog_protect
        if rate_limit:
            cli += ' rate-limit ' + rate_limit

    if mod_action in ['create', 'delete', 'modify']:
        if name:
            cli += ' name ' + name

    run_cli(module, cli)

if __name__ == '__main__':
    main()
