#!/usr/bin/python
""" PN CLI admin-session-timeout-modify """
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
module: pn_admin_session_timeout
author: "Pluribus Networks (devops@pluribusnetworks.com)"
version: 2
short_description: CLI command to modify admin-session-timeout.
description:
  - C(modify): Modify login session timeout
options:
  pn_cliswitch:
    description:
      - Target switch to run the CLI on.
    required: False
    type: str
  action:
    description:
      - admin-session-timeout configuration command.
    required: true
    choices: ['modify']
    type: str
  pn_timeout:
    description:
      - Maximum time to wait for user activity before terminating login session
    required: false
    type: str
"""

EXAMPLES = """
- name: admin session timeout functionality
  pn_admin_session_timeout:
    action: "modify"
    pn_timeout: '3600'
"""

RETURN = """
command:
  description: the CLI command run on the target node.
stdout:
  description: set of responses from the admin-session-timeout command.
  returned: always
  type: list
stderr:
  description: set of error responses from the admin-session-timeout command.
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
            msg="admin-session-timeout %s operation failed" % action,
            changed=False
        )

    if out:
        module.exit_json(
            command=' '.join(cli),
            stdout=out.strip(),
            msg="admin-session-timeout %s operation completed" % action,
            changed=True
        )

    else:
        module.exit_json(
            command=' '.join(cli),
            msg="admin-session-timeout %s operation completed" % action,
            changed=True
        )


def main():
    """ This section is for arguments parsing """
    module = AnsibleModule(
        argument_spec=dict(
            pn_cliswitch=dict(required=False, type='str'),
            action=dict(required=True, type='str', choices=['modify']),
            pn_timeout=dict(required=False, type='str'),
        )
    )

    # Accessing the arguments
    switch = module.params['pn_cliswitch']
    mod_action = module.params['action']
    timeout = module.params['pn_timeout']

    # Building the CLI command string
    cli = pn_cli(module, switch)
    cli += ' admin-session-timeout-' + mod_action
    if mod_action in ['modify']:
        if timeout:
            cli += ' timeout ' + timeout
    run_cli(module, cli)

if __name__ == '__main__':
    main()
