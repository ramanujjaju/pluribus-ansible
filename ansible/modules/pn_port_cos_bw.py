#!/usr/bin/python
""" PN CLI port-cos-bw-modify """

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
module: pn_port_cos_bw
author: "Pluribus Networks (devops@pluribusnetworks.com)"
version: 2
short_description: CLI command to modify port-cos-bw.
description:
  - C(modify): Update b/w settings for CoS queues
options:
  pn_cliswitch:
    description:
      - Target switch to run the CLI on.
    required: False
    type: str
  pn_action:
    description:
      - port-cos-bw configuration command.
    required: true
    choices: ['modify']
    type: str
  pn_max_bw_limit:
    description:
      - Maximum b/w in %
    required: false
    type: str
  pn_cos:
    description:
      - CoS priority
    required: false
    type: str
  pn_port:
    description:
      - physical port
    required: false
    type: str
  pn_weight:
    description:
      - Scheduling weight after b/w guarantee met
    required: false
    type: str
  pn_min_bw_guarantee:
    description:
      - Minimum b/w in %
    required: false
    type: str
"""

EXAMPLES = """
- name: port cos bw modify
  pn_port_cos_bw:
    pn_cliswitch: "{{ inventory_hostname }}"
    pn_action: "modify"
    pn_port: "all"
    pn_cos: "4"
    pn_min_bw_guarantee: "8"
"""

RETURN = """
command:
  description: the CLI command run on the target node.
stdout:
  description: set of responses from the port-cos-bw command.
  returned: always
  type: list
stderr:
  description: set of error responses from the port-cos-bw command.
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
            msg="port-cos-bw %s operation failed" % action,
            changed=False
        )

    if out:
        module.exit_json(
            command=' '.join(cli),
            stdout=out.strip(),
            msg="port-cos-bw %s operation completed" % action,
            changed=True
        )

    else:
        module.exit_json(
            command=' '.join(cli),
            msg="port-cos-bw %s operation completed" % action,
            changed=True
        )


def main():
    """ This section is for arguments parsing """
    module = AnsibleModule(
        argument_spec=dict(
            pn_cliswitch=dict(required=False, type='str'),
            pn_action=dict(required=True, type='str', choices=['modify']),
            pn_max_bw_limit=dict(required=False, type='str'),
            pn_cos=dict(required=False, type='str'),
            pn_port=dict(required=False, type='str'),
            pn_weight=dict(required=False, type='str'),
            pn_min_bw_guarantee=dict(required=False, type='str'),
        )
    )

    # Accessing the arguments
    switch = module.params['pn_cliswitch']
    mod_action = module.params['pn_action']
    max_bw_limit = module.params['pn_max_bw_limit']
    cos = module.params['pn_cos']
    port = module.params['pn_port']
    weight = module.params['pn_weight']
    min_bw_guarantee = module.params['pn_min_bw_guarantee']

    # Building the CLI command string
    cli = pn_cli(module, switch)
    cli += ' port-cos-bw-' + mod_action
    if mod_action in ['modify']:
        if max_bw_limit:
            cli += ' max-bw-limit ' + max_bw_limit
        if cos:
            cli += ' cos ' + cos
        if port:
            cli += ' port ' + port
        if weight:
            cli += ' weight ' + weight
        if min_bw_guarantee:
            cli += ' min-bw-guarantee ' + min_bw_guarantee

    run_cli(module, cli)

if __name__ == '__main__':
    main()
