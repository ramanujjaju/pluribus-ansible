#!/usr/bin/python
""" PN CLI role-create/modify/delete """
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
module: pn_role
author: "Pluribus Networks (devops@pluribusnetworks.com)"
version: 2
short_description: CLI command to create/modify/delete role.
description:
  - C(create): create user roles
  - C(modify): modify user roles
  - C(delete): delete user roles
options:
  pn_cliswitch:
    description:
      - Target switch to run the CLI on.
    required: False
    type: str
  action:
    description:
      - role configuration command.
    required: true
    choices: ['create', 'modify', 'delete']
    type: str
  pn_scope:
    description:
      - local or fabric
    required: false
    choices: ['local', 'fabric']
  pn_access:
    description:
      - type of access - default read-write
    required: false
    choices: ['read-only', 'read-write']
  pn_shell:
    description:
      - allow shell command
    required: false
    type: bool
  pn_sudo:
    description:
      - allow sudo from shell
    required: false
    type: bool
  pn_running_config:
    description:
      - display running configuration of switch
    required: false
    type: bool
  pn_name:
    description:
      - role name
    required: false
    type: str
  pn_delete_from_users:
    description:
      - delete from users
    required: false
    type: str
"""

EXAMPLES = """
- name: role functionality
  pn_role:
    action: "create"
    pn_name: "abcd"
    pn_scope: "local"
"""

RETURN = """
command:
  description: the CLI command run on the target node.
stdout:
  description: set of responses from the role command.
  returned: always
  type: list
stderr:
  description: set of error responses from the role command.
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
        module.exit_json(
            command=' '.join(cli),
            stderr=err.strip(),
            msg="role %s operation failed" % action,
            changed=False
        )

    if out:
        module.exit_json(
            command=' '.join(cli),
            stdout=out.strip(),
            msg="role %s operation completed" % action,
            changed=True
        )

    else:
        module.exit_json(
            command=' '.join(cli),
            msg="role %s operation completed" % action,
            changed=True
        )


def main():
    """ This section is for arguments parsing """
    module = AnsibleModule(
        argument_spec=dict(
            pn_cliswitch=dict(required=False, type='str'),
            action=dict(required=True, type='str',
                        choices=['create', 'modify', 'delete']),
            pn_scope=dict(required=False, type='str',
                          choices=['local', 'fabric']),
            pn_access=dict(required=False, type='str',
                           choices=['read-only', 'read-write']),
            pn_shell=dict(required=False, type='bool'),
            pn_sudo=dict(required=False, type='bool'),
            pn_running_config=dict(required=False, type='bool'),
            pn_name=dict(required=False, type='str'),
            pn_delete_from_users=dict(required=False, type='str'),
        )
    )

    # Accessing the arguments
    switch = module.params['pn_cliswitch']
    mod_action = module.params['action']
    scope = module.params['pn_scope']
    access = module.params['pn_access']
    shell = module.params['pn_shell']
    sudo = module.params['pn_sudo']
    running_config = module.params['pn_running_config']
    name = module.params['pn_name']
    delete_from_users = module.params['pn_delete_from_users']

    # Building the CLI command string
    cli = pn_cli(module, switch)
    cli += ' role-' + mod_action
    if mod_action in ['create']:
        if scope:
            cli += ' scope ' + scope
    if mod_action in ['create', 'modify']:
        if access:
            cli += ' access ' + access
        if shell:
            if shell is True:
                cli += ' shell '
            else:
                cli += ' no-shell '
        if sudo:
            if sudo is True:
                cli += ' sudo '
            else:
                cli += ' no-sudo '
        if running_config:
            if running_config is True:
                cli += ' running-config '
            else:
                cli += ' no-running-config '
    if mod_action in ['create', 'delete', 'modify']:
        if name:
            cli += ' name ' + name

    if mod_action in ['modify']:
        if delete_from_users:
            cli += ' delete-from-users ' + delete_from_users

    run_cli(module, cli)

if __name__ == '__main__':
    main()
