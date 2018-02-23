#!/usr/bin/python
""" PN CLI port-cos-rate-setting-modify """
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
module: pn_port_cos_rate_setting
author: "Pluribus Networks (devops@pluribusnetworks.com)"
version: 2
short_description: CLI command to modify port-cos-rate-setting.
description:
  - C(modify): update the port cos rate limit
options:
  pn_cliswitch:
    description:
      - Target switch to run the CLI on.
    required: False
    type: str
  action:
    description:
      - port-cos-rate-setting configuration command.
    required: true
    choices: ['modify']
    type: str
  pn_cos1_rate:
    description:
      - cos1 rate limit (pps)
    required: false
    type: str
  pn_cos5_rate:
    description:
      - cos5 rate limit (pps)
    required: false
    type: str
  pn_cos2_rate:
    description:
      - cos2 rate limit (pps)
    required: false
    type: str
  pn_cos0_rate:
    description:
      - cos0 rate limit (pps)
    required: false
    type: str
  pn_cos6_rate:
    description:
      - cos6 rate limit (pps)
    required: false
    type: str
  pn_cos3_rate:
    description:
      - cos3 rate limit (pps)
    required: false
    type: str
  pn_cos4_rate:
    description:
      - cos4 rate limit (pps)
    required: false
    type: str
  pn_cos7_rate:
    description:
      - cos7 rate limit (pps)
    required: false
    type: str
  pn_port:
    description:
      - port
    required: false
    choices: ['control-port', 'data-port', 'span-ports']
"""

EXAMPLES = """
pn_port_cos_rate_setting:
  pn_cliswitch: "{{ inventory_hostname }}"
  pn_action: "modify"
  pn_port: "control-port"
  pn_cos1_rate: "1000"
  pn_cos5_rate: "1000"
  pn_cos2_rate: "1000"
  pn_cos0_rate: "1000"
  pn_cos6_rate: "1000"
  pn_cos3_rate: "1000"
  pn_cos4_rate: "1000"
  pn_cos7_rate: "1000" 
"""

RETURN = """
command:
  description: the CLI command run on the target node.
stdout:
  description: set of responses from the port-cos-rate-setting command.
  returned: always
  type: list
stderr:
  description: set of error responses from the port-cos-rate-setting command.
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
            msg="port-cos-rate-setting %s operation failed" % action,
            changed=False
        )

    if out:
        module.exit_json(
            command=' '.join(cli),
            stdout=out.strip(),
            msg="port-cos-rate-setting %s operation completed" % action,
            changed=True
        )

    else:
        module.exit_json(
            command=' '.join(cli),
            msg="port-cos-rate-setting %s operation completed" % action,
            changed=True
        )


def main():
    """ This section is for arguments parsing """
    module = AnsibleModule(
        argument_spec=dict(
            pn_cliswitch=dict(required=False, type='str'),
            pn_action=dict(required=True, type='str', choices=['modify']),
            pn_cos1_rate=dict(required=False, type='str'),
            pn_cos5_rate=dict(required=False, type='str'),
            pn_cos2_rate=dict(required=False, type='str'),
            pn_cos0_rate=dict(required=False, type='str'),
            pn_cos6_rate=dict(required=False, type='str'),
            pn_cos3_rate=dict(required=False, type='str'),
            pn_cos4_rate=dict(required=False, type='str'),
            pn_cos7_rate=dict(required=False, type='str'),
            pn_port=dict(required=False, type='str', choices=['control-port', \
                         'data-port', 'span-ports']),
        )
    )

    # Accessing the arguments
    mod_action = module.params['pn_action']
    cos1_rate = module.params['pn_cos1_rate']
    cos5_rate = module.params['pn_cos5_rate']
    cos2_rate = module.params['pn_cos2_rate']
    cos0_rate = module.params['pn_cos0_rate']
    cos6_rate = module.params['pn_cos6_rate']
    cos3_rate = module.params['pn_cos3_rate']
    cos4_rate = module.params['pn_cos4_rate']
    cos7_rate = module.params['pn_cos7_rate']
    port = module.params['pn_port']

    # Building the CLI command string
    cli = pn_cli(module)
    cli += 'port-cos-rate-setting-' + mod_action
    if mod_action in ['modify']:
        if cos1_rate:
            cli += ' cos1-rate ' + cos1_rate
        if cos5_rate:
            cli += ' cos5-rate ' + cos5_rate
        if cos2_rate:
            cli += ' cos2-rate ' + cos2_rate
        if cos0_rate:
            cli += ' cos0-rate ' + cos0_rate
        if cos6_rate:
            cli += ' cos6-rate ' + cos6_rate
        if cos3_rate:
            cli += ' cos3-rate ' + cos3_rate
        if cos4_rate:
            cli += ' cos4-rate ' + cos4_rate
        if cos7_rate:
            cli += ' cos7-rate ' + cos7_rate
        if port:
            cli += ' port ' + port

    run_cli(module, cli)

if __name__ == '__main__':
    main()
