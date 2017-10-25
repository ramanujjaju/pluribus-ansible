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


def pn_cli(module):
    """
    This method is to generate the cli portion to launch the Netvisor cli.
    It parses the username, password, switch parameters from module.
    :param module: The Ansible module to fetch username, password and switch
    :return: returns the cli string for further processing
    """
    username = module.params['pn_cliusername']
    password = module.params['pn_clipassword']
    cliswitch = module.params['pn_cliswitch']

    cli = '/usr/bin/cli --quiet '

    if username and password:
        cli += '--user "%s":"%s" ' % (username, password)

    if cliswitch:
        cli += ' switch ' + cliswitch

    cli += ' admin-syslog-'

    return cli


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


def check_community(module, name):
    cli = pn_cli(module)
    cli += 'show name ' + name
    cli = shlex.split(cli)
    return module.run_command(cli)[1]


def main():
    """ This section is for arguments parsing """
    module = AnsibleModule(
        argument_spec=dict(
            pn_cliusername=dict(required=False, type='str', no_log=True),
            pn_clipassword=dict(required=False, type='str', no_log=True),
            pn_cliswitch=dict(required=False, type='str'),
            pn_action=dict(required=True, type='str', choices=['create', 'delete', 'modify']),
            pn_name=dict(required=True, type='str'),
            pn_scope=dict(required=False, type='str', choices=['local', 'fabric']),
            pn_host=dict(required=False, type='str'),
            pn_port=dict(required=False, type='str'),
            pn_transport=dict(required=False, type='str', choices=['tcp-tls', 'udp']),
            pn_message_format=dict(required=False, type='str', choices=['structured', 'legacy']),
        )
    )

    name = module.params['pn_name']
    action = module.params['pn_action']
    scope = module.params['pn_scope']
    host = module.params['pn_host']
    port = module.params['pn_port']
    transport = module.params['pn_transport']
    message_format = module.params['pn_message_format']

    if action == 'create':
        if check_community(module, name):
            module.fail_json(
                msg='admin-syslog with name %s already present in the switch' % name
            )
    elif action == 'modify' or action == 'delete':
        if not check_community(module, name):
            module.fail_json(
                msg='admin-syslog with name %s not present in the switch' % name
            )
    else:
        module.fail_json(
            msg='admin-syslog action %s not supported. Use create/delete/modify' % action
        )

    cli = pn_cli(module)
    cli += action + ' name ' + name
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
