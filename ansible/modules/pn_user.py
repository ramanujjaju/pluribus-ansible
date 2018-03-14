#!/usr/bin/python
""" PN CLI user-create/modify/delete """

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

import os
import shlex
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.pn_nvos import pn_cli

DOCUMENTATION = """
---
module: pn_user
author: "Pluribus Networks (devops@pluribusnetworks.com)"
version: 2
short_description: CLI command to create/modify/delete user.
description:
  - C(create): create a user and apply a role
  - C(modify): update a user
  - C(delete): delete a user
options:
  pn_cliswitch:
    description:
      - Target switch to run the CLI on.
    required: False
    type: str
  pn_action:
    description:
      - user configuration command.
    required: true
    choices: ['create', 'modify', 'delete']
    type: str
  pn_scope:
    description:
      - local or fabric
    required: false
    choices: ['local', 'fabric']
  pn_initial_role:
    description:
      - initial role for user
    required: false
    type: str
    choices: ['network-admin', 'read-only-network-admin']
  pn_password:
    description:
      - plain text password
    required: false
    type: str
  pn_name:
    description:
      - username
    required: false
    type: str
"""

EXAMPLES = """
- name: Create a user
  pn_user:
    pn_action: 'create'
    pn_name: 'system-admin'
    pn_scope: 'fabric'
    pn_initial_role: 'network-admin'
    pn_password: "{{ secret_password }}"
    
- name: Delete a user
  pn_user:
    pn_action: 'delete'
    pn_name: 'system-admin'
"""

RETURN = """
command:
  description: the CLI command run on the target node.
stdout:
  description: set of responses from the user command.
  returned: always
  type: list
stderr:
  description: set of error responses from the user command.
  returned: on error
  type: list
changed:
  description: indicates whether the CLI caused changes on the target.
  returned: always
  type: bool
"""


def run_cli(module, cli, pass_args=None):
    """
    This method executes the cli command on the target node(s) and returns the
    output. The module then exits based on the output.
    :param cli: the complete cli string to be executed on the target node(s).
    :param module: The Ansible module to fetch command
    """
    action = module.params['pn_action']
    if pass_args:
        fd_r, fd_w = os.pipe()
        newpid = os.fork()
        if newpid == 0:
           os.close(fd_w)
           cli = cli.replace('--quiet -e --no-login-prompt', '--quiet  --pass-fd %s ' % (fd_r))
           cli = shlex.split(cli)
           rc, out, err = module.run_command(cli, close_fds=False)
           os.close(fd_r)
        else:
           os.close(fd_r)
           os.write(fd_w, pass_args)
           os.close(fd_w)
    else:
        cli = shlex.split(cli)
        rc, out, err = module.run_command(cli)

    # Response in JSON format
    if err:
        module.fail_json(
            command=' '.join(cli),
            stderr=err.strip(),
            msg="user %s operation failed" % action,
            changed=False
        )

    if out:
        module.exit_json(
            command=' '.join(cli),
            stdout=out.strip(),
            msg="user %s operation completed" % action,
            changed=True
        )

    else:
        module.exit_json(
            command=' '.join(cli),
            msg="user %s operation completed" % action,
            changed=True
        )


def check_user(module):
    """

    :param module:
    :return:
    """
    name = module.params['pn_name']
    show_cli = pn_cli(module)
    show_cli += ' user-show name %s' % name
    show_cli = shlex.split(show_cli)
    return module.run_command(show_cli)[1]


def main():
    """ This section is for arguments parsing """
    module = AnsibleModule(
        argument_spec=dict(
            pn_cliswitch=dict(required=False, type='str'),
            pn_action=dict(required=True, type='str',
                           choices=['create', 'modify', 'delete']),
            pn_scope=dict(required=False, type='str',
                          choices=['local', 'fabric']),
            pn_initial_role=dict(required=False, type='str', default='network-admin',
                                 choices=['network-admin', 'read-only-network-admin']),
            pn_password=dict(required=False, type='str', no_log=True),
            pn_name=dict(required=False, type='str'),
        )
    )

    # Accessing the arguments
    mod_action = module.params['pn_action']
    scope = module.params['pn_scope']
    initial_role = module.params['pn_initial_role']
    password = module.params['pn_password']
    name = module.params['pn_name']

    # Building the CLI command string
    cli = pn_cli(module)
    cli += 'user-' + mod_action

    pass_args = ""
    if mod_action in ['create']:
        if check_user(module):
            module.exit_json(
                msg='user %s already exists on the switch' % name
            )
        if scope:
            cli += ' scope ' + scope
        if initial_role:
            cli += ' initial-role ' + initial_role

    if mod_action in ['create', 'delete', 'modify']:
        if name:
            cli += ' name ' + name

    if mod_action in ['create', 'modify']:
        if password:
            pass_args += ' password %s ' % (password)

    run_cli(module, cli, pass_args)

if __name__ == '__main__':
    main()
