#!/usr/bin/python
""" PN CLI snmp-user-create/snmp-user-delete """
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
import os
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.pn_nvos import pn_cli

DOCUMENTATION = """
---
module: pn_snmp_user
author: "Pluribus Networks (devops@pluribusnetworks.com)"
version: 2
short_description: CLI command to create/modify/delete snmp-user.
description:
  - C(create): create View Access Control Models (VACM)
  - C(modify): modify View Access Control Models (VACM)
  - C(delete): delete View Access Control Models (VACM)
options:
  pn_cliswitch:
    description:
      - Target switch to run the CLI on.
    required: False
    type: str
  action:
    description:
      - snmp-user configuration command.
    required: true
    choices: ['create', 'modify', 'delete']
    type: str
  pn_priv:
    description:
      - privileges
    required: false
    type: bool
  pn_auth:
    description:
      - authentication required
    required: false
    type: bool
  pn_user_type:
    description:
      - SNMP user type
    required: false
    choices: ['rouser', 'rwuser']
  pn_user_name:
    description:
      - SNMP administrator name
    required: false
    type: str
  pn_auth_pass:
    description:
      - snmp authentication password
    required: False
    type: str
  pn_priv_pass:
    description:
      - snmp privilege password
    required: False
    type: str
"""

EXAMPLES = """
- name: snmp-user functionality
  pn_snmp_user:
    pn_action: "create"
    pn_user_name: "VINETrw"      
    pn_auth: True
    pn_priv: True
    pn_auth_pass: 'baseball'
    pn_priv_pass: 'baseball'
"""

RETURN = """
command:
  description: the CLI command run on the target node.
stdout:
  description: set of responses from the snmp-user command.
  returned: always
  type: list
stderr:
  description: set of error responses from the snmp-user command.
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
            msg="snmp-user %s operation failed" % action,
            changed=False
        )

    if out:
        module.exit_json(
            command=' '.join(cli),
            stdout=out.strip(),
            msg="snmp-user %s operation completed" % action,
            changed=True
        )

    else:
        module.exit_json(
            command=' '.join(cli),
            msg="snmp-user %s operation completed" % action,
            changed=True
        )


def check_user(module, user_name):
    """
    This method is to checks user exists or not.
    :param user_name: the user to be checked.
    :return: String of user if exists else Success.
    """
    cli = pn_cli(module)
    cli += 'snmp-user-show user-name ' + user_name
    cli = shlex.split(cli)
    return module.run_command(cli)[1]


def main():
    """ This section is for arguments parsing """
    module = AnsibleModule(
        argument_spec=dict(
            pn_cliswitch=dict(required=False, type='str'),
            pn_action=dict(required=True, type='str',
                           choices=['create', 'delete', 'modify']),
            pn_user_name=dict(required=True, type='str'),
            pn_auth=dict(required=False, type='bool', default=False),
            pn_priv=dict(required=False, type='bool', default=False),
            pn_auth_pass=dict(required=False, type='str', no_log=True),
            pn_priv_pass=dict(required=False, type='str', no_log=True),
            pn_auth_hash=dict(required=False, type='str',
                              choices=['sha', 'md5']),
        )
    )

    pass_args = ''
    user_name = module.params['pn_user_name']
    action = module.params['pn_action']
    auth = module.params['pn_auth']
    priv = module.params['pn_priv']
    auth_pass = module.params['pn_auth_pass']
    priv_pass = module.params['pn_priv_pass']
    auth_hash = module.params['pn_auth_hash']

    if action == 'create':
        if check_user(module, user_name):
            module.exit_json(
                msg='snmp-user with name %s \
                     already present in the switch' % user_name
            )
    elif action == 'delete' or action == 'modify':
        if not check_user(module, user_name):
            module.fail_json(
                msg='snmp-user with name %s \
                     not present in the switch' % user_name
            )
    else:
        module.fail_json(
            msg='snmp-user action %s not supported \
                 in this playbook. Use create/delete' % action
        )

    cli = pn_cli(module)
    cli += ' snmp-user-'+ action + ' user-name ' + user_name

    pass_args = ""
    if action != 'delete':
        if auth or auth_hash:
            cli += ' auth'
            cli += ' auth-password'
	    pass_args += 'auth-password %s ' % (auth_pass)
            if auth_hash:
                cli += ' auth-hash %s' % auth_hash
        else:
            cli += ' no-auth'

        if priv:
            cli += ' priv'
            cli += ' priv-password'
	    pass_args += 'priv-password %s' % (priv_pass)
        else:
            cli += ' no-priv'

    run_cli(module, cli, pass_args)

if __name__ == '__main__':
    main()
