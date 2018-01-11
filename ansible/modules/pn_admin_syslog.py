#!/usr/bin/python
""" PN CLI admin-syslog-create/admin-syslog-modify/admin-syslog-delete """
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
module: pn_admin_syslog.py
author: 'Pluribus Networks (devops@pluribusnetworks.com)'
short_description: Module to create/delete/modify admin syslog.
description:
    It performs following steps:
        - creates/deletes/modifies admin syslogs.
options:
  pn_cliswitch:
    description:
      - Target switch to run the CLI on.
    required: False
    type: str
    pn_action:
      description:
        - Action required on admin syslog.
      required: True
      type: str
      choice: ['create', 'delete', 'modify']
    pn_name:
      description:
        - Specify the name of admin syslog.
      required: True
      type: str
    pn_scope:
      description:
        - Specify the scope of admin syslog.
      required: False
      type: str
      choice: ['local', 'fabric']
    pn_host:
      description:
        - Specify the host ip of admin syslog.
      required: False
      type: str
    pn_port:
      description:
        - Specify the port of admin syslog.
      required: False
      type: str
    pn_transport:
      description:
        - Specify the transport of admin syslog.
      required: False
      type: str
      choice: ['tcp-tls', 'udp']
    pn_message_format:
      description:
        - Specify the message format of admin syslog.
      required: False
      type: str
      choice: ['structured', 'legacy']
"""

EXAMPLES = """
- name: admin-syslog functionality
  pn_admin_syslog:
   pn_action: "create"
   pn_name: "vzsyslog"
   pn_scope: "fabric"
   pn_host: "146.13.191.77"
   pn_message_format: 'structured'
"""

RETURN = """
summary:
  description: It contains output of each configuration along with switch name.
  returned: always
  type: str
changed:
  description: Indicates whether the CLI caused changes on the target.
  returned: always
  type: bool
unreachable:
  description: Indicates whether switch was unreachable to connect.
  returned: always
  type: bool
failed:
  description: Indicates whether or not the execution failed on the target.
  returned: always
  type: bool
exception:
  description: Describes error/exception occurred while executing CLI command.
  returned: always
  type: str
task:
  description: Name of the task getting executed on switch.
  returned: always
  type: str
msg:
  description: Indicates whether configuration made was successful or failed.
  returned: always
  type: str
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
        module.exit_json(
            command=' '.join(cli),
            stderr=err.strip(),
            msg="admin-syslog %s operation failed" % action,
            changed=False
        )

    if out:
        module.exit_json(
            command=' '.join(cli),
            stdout=out.strip(),
            msg="admin-syslog %s operation completed" % action,
            changed=True
        )

    else:
        module.exit_json(
            command=' '.join(cli),
            msg="admin-syslog %s operation completed" % action,
            changed=True
        )


def check_admin_syslog(module, name):
    """
    Method to chaeck admin syslog name.
    :param module: The Ansible module to fetch input parameters.
    :param name: name of syslog.
    :return: The output of run_cli() method.
    """

    cli = pn_cli(module, module.params['pn_cliswitch'])
    cli += ' admin-syslog-show name ' + name
    cli = shlex.split(cli)
    return module.run_command(cli)[1]


def main():
    """ This section is for arguments parsing """
    module = AnsibleModule(
        argument_spec=dict(
            pn_cliswitch=dict(required=False, type='str'),
            pn_action=dict(required=True, type='str',
                           choices=['create', 'delete', 'modify']),
            pn_name=dict(required=True, type='str'),
            pn_scope=dict(required=False, type='str',
                          choices=['local', 'fabric']),
            pn_host=dict(required=False, type='str'),
            pn_port=dict(required=False, type='str'),
            pn_transport=dict(required=False, type='str',
                              choices=['tcp-tls', 'udp']),
            pn_message_format=dict(required=False, type='str',
                                   choices=['structured', 'legacy']),
        )
    )

    switch = module.params['pn_cliswitch']
    name = module.params['pn_name']
    action = module.params['pn_action']
    scope = module.params['pn_scope']
    host = module.params['pn_host']
    port = module.params['pn_port']
    transport = module.params['pn_transport']
    message_format = module.params['pn_message_format']

    if action == 'create':
        if check_admin_syslog(module, name):
            module.exit_json(
                msg='admin-syslog with name %s
                     already present in the switch' % name
            )
    elif action == 'modify' or action == 'delete':
        if not check_admin_syslog(module, name):
            module.fail_json(
                msg='admin-syslog with name %s \
                     not present in the switch' % name
            )
    else:
        module.fail_json(
            msg='admin-syslog action %s not supported. \
                 Use create/delete/modify' % action
        )

    cli = pn_cli(module, switch)
    cli += ' admin-syslog-' + action + ' name ' + name
    if action != 'delete':
        if scope:
            cli += ' scope ' + scope

        if host:
            cli += ' host ' + host

        if port:
            cli += ' port ' + port

        if transport:
            cli += ' transport ' + transport

        if message_format:
            cli += ' message-format ' + message_format

    run_cli(module, cli)

if __name__ == '__main__':
    main()
