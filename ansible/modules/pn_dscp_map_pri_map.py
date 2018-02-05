#!/usr/bin/python
""" PN CLI dscp-map-pri-map-modify """

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
module: pn_dscp_map_pri_map
author: "Pluribus Networks (devops@pluribusnetworks.com)"
version: 2
short_description: CLI command to modify dscp-map-pri-map.
description:
  - C(modify): Update priority mappings in tables
options:
  pn_cliswitch:
    description:
      - Target switch to run the CLI on.
    required: False
    type: str
  pn_action:
    description:
      - dscp-map-pri-map configuration command.
    required: true
    choices: ['modify']
    type: str
  pn_pri:
    description:
      - CoS priority
    required: false
    type: str
  pn_name:
    description:
      - Name for the DSCP map
    required: false
    type: str
  pn_dsmap:
    description:
      - DSCP value(s)
    required: false
    type: str
"""

EXAMPLES = """
- name: dscp map pri map modify
  pn_dscp_map_pri_map:
    pn_cliswitch: "{{ inventory_hostname }}"
    pn_action: "modify"
    pn_name: "verizon_qos"
    pn_pri: "0"
    pn_dsmap: "1-60"
"""

RETURN = """
command:
  description: the CLI command run on the target node.
stdout:
  description: set of responses from the dscp-map-pri-map command.
  returned: always
  type: list
stderr:
  description: set of error responses from the dscp-map-pri-map command.
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
            msg="dscp-map-pri-map %s operation failed" % action,
            changed=False
        )

    if out:
        module.exit_json(
            command=' '.join(cli),
            stdout=out.strip(),
            msg="dscp-map-pri-map %s operation completed" % action,
            changed=True
        )

    else:
        module.exit_json(
            command=' '.join(cli),
            msg="dscp-map-pri-map %s operation completed" % action,
            changed=True
        )


def main():
    """ This section is for arguments parsing """
    module = AnsibleModule(
        argument_spec=dict(
            pn_cliswitch=dict(required=False, type='str'),
            pn_action=dict(required=True, type='str', choices=['modify']),
            pn_pri=dict(required=False, type='str'),
            pn_name=dict(required=False, type='str'),
            pn_dsmap=dict(required=False, type='str'),
        )
    )

    # Accessing the arguments
    switch = module.params['pn_cliswitch']
    mod_action = module.params['pn_action']
    pri = module.params['pn_pri']
    name = module.params['pn_name']
    dsmap = module.params['pn_dsmap']

    # Building the CLI command string
    cli = pn_cli(module, switch)
    cli += ' dscp-map-pri-map-' + mod_action
    if mod_action in ['modify']:
        if pri:
            cli += ' pri ' + pri
        if name:
            cli += ' name ' + name
        if dsmap:
            cli += ' dsmap ' + dsmap

    run_cli(module, cli)

if __name__ == '__main__':
    main()
