#!/usr/bin/python
""" PN CLI stp-port-modify """

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
module: pn_stp_port
author: "Pluribus Networks (devops@pluribusnetworks.com)"
version: 2
short_description: CLI command to modify stp-port.
description:
  - C(modify): modify Spanning Tree Protocol (STP) parameters
options:
  pn_cliswitch:
    description:
      - Target switch to run the CLI on.
    required: False
    type: str
  pn_action:
    description:
      - stp-port configuration command.
    required: true
    choices: ['modify']
    type: str
  pn_priority:
    description:
      - STP port priority from 0 to 240 - default 128
    required: false
    type: str
  pn_cost:
    description:
      - STP port cost from 1 to 200000000 - default 2000
    required: false
    type: str
  pn_root_guard:
    description:
      - STP port Root guard
    required: false
    type: bool
  pn_filter:
    description:
      - STP port filters BPDUs
    required: false
    type: bool
  pn_edge:
    description:
      - STP port is an edge port
    required: false
    type: bool
  pn_bpdu_guard:
    description:
      - STP port BPDU guard
    required: false
    type: bool
  pn_port:
    description:
      - STP port
    required: false
    type: str
  pn_block:
    description:
      - Specify if a STP port blocks BPDUs
    required: false
    type: bool
"""

EXAMPLES = """
    - name: Modify stp
      pn_stp_port:
        pn_action: "modify"
        pn_port: "2,3"
        pn_cost: "200"
"""

RETURN = """
command:
  description: the CLI command run on the target node.
stdout:
  description: set of responses from the stp-port command.
  returned: always
  type: list
stderr:
  description: set of error responses from the stp-port command.
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
            msg="stp-port %s operation failed" % action,
            changed=False
        )

    if out:
        module.exit_json(
            command=' '.join(cli),
            stdout=out.strip(),
            msg="stp-port %s operation completed" % action,
            changed=True
        )

    else:
        module.exit_json(
            command=' '.join(cli),
            msg="stp-port %s operation completed" % action,
            changed=True
        )


def main():
    """ This section is for arguments parsing """
    module = AnsibleModule(
        argument_spec=dict(
            pn_cliswitch=dict(required=False, type='str'),
            pn_action=dict(required=True, type='str', choices=['modify']),
            pn_priority=dict(required=False, type='str'),
            pn_cost=dict(required=False, type='str'),
            pn_root_guard=dict(required=False, type='bool'),
            pn_filter=dict(required=False, type='bool'),
            pn_edge=dict(required=False, type='bool'),
            pn_bpdu_guard=dict(required=False, type='bool'),
            pn_port=dict(required=False, type='str'),
            pn_block=dict(required=False, type='bool'),
        )
    )

    # Accessing the arguments
    mod_action = module.params['pn_action']
    priority = module.params['pn_priority']
    cost = module.params['pn_cost']
    root_guard = module.params['pn_root_guard']
    filter = module.params['pn_filter']
    edge = module.params['pn_edge']
    bpdu_guard = module.params['pn_bpdu_guard']
    port = module.params['pn_port']
    block = module.params['pn_block']

    # Building the CLI command string
    cli = pn_cli(module)
    cli += 'stp-port-' + mod_action
    if mod_action in ['modify']:
        if priority:
            cli += ' priority ' + priority
        if cost:
            cli += ' cost ' + cost
        if root_guard:
            if root_guard is True:
                cli += ' root-guard '
            else:
                cli += ' no-root-guard '
        if filter:
            if filter is True:
                cli += ' filter '
            else:
                cli += ' no-filter '
        if edge:
            if edge is True:
                cli += ' edge '
            else:
                cli += ' no-edge '
        if bpdu_guard:
            if bpdu_guard is True:
                cli += ' bpdu-guard '
            else:
                cli += ' no-bpdu-guard '
        if port:
            cli += ' port ' + port
        if block:
            if block is True:
                cli += ' block '
            else:
                cli += ' no-block '
    
    run_cli(module, cli)

if __name__ == '__main__':
    main()
