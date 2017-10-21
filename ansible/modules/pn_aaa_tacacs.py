#!/usr/bin/python
""" PN CLI aaa-tacacs-create/aaa-tacacs-delete/aaa-tacacs-modify """
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

    cli += ' aaa-tacacs-'

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
            msg="aaa-tacacs %s operation failed" % action,
            changed=False
        )

    if out:
        module.exit_json(
            command=' '.join(cli),
            stdout=out.strip(),
            msg="aaa-tacacs %s operation completed" % action,
            changed=True
        )

    else:
        module.exit_json(
            command=' '.join(cli),
            msg="aaa-tacacs %s operation completed" % action,
            changed=True
        )


def check_aaa(module, name):
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
            pn_scope=dict(required=False, type='str', choices=['local', 'fabric']),
            pn_authen_method=dict(required=False, type='str', choices=['pap', 'chap', 'ms-chap']),
            pn_name=dict(required=True, type='str'),
            pn_server=dict(required=False, type='str'),
            pn_port=dict(required=False, type='str'),
            pn_secret=dict(required=False, type='str'),
            pn_priority=dict(required=False, type='str'),
            pn_service=dict(required=False, type='str'),
            pn_service_shell=dict(required=False, type='str'),
            pn_service_vtysh=dict(required=False, type='str'),
            pn_authen=dict(type='bool'),
            pn_authen_local=dict(type='bool'),
            pn_sess_acct=dict(type='bool'),
            pn_cmd_acct=dict(type='bool'),
            pn_acct_local=dict(type='bool'),
            pn_author_local=dict(type='bool'),
            pn_cmd_author=dict(type='bool'),
            pn_sess_author=dict(type='bool'),
        )
    )


    name = module.params['pn_name']
    action = module.params['pn_action']
    scope = module.params['pn_scope']
    server = module.params['pn_server']
    port = module.params['pn_port']
    secret = module.params['pn_secret']
    priority = module.params['pn_priority']
    authen_method = module.params['pn_authen_method']
    service = module.params['pn_service']
    service_shell = module.params['pn_service_shell']
    service_vtysh = module.params['pn_service_vtysh']
    authen = module.params['pn_authen']
    authen_local = module.params['pn_authen_local']
    sess_acct = module.params['pn_sess_acct']
    cmd_acct = module.params['pn_cmd_acct']
    acct_local = module.params['pn_acct_local']
    author_local = module.params['pn_author_local']
    cmd_author = module.params['pn_cmd_author']
    sess_author = module.params['pn_sess_author']

    if action == 'create':
        if check_aaa(module, name):
            module.fail_json(
                msg='aaa-tacacs with name %s already present in the switch' % name
            )
    elif action == 'modify' or action == 'delete':
        if not check_aaa(module, name):
            module.fail_json(
                msg='aaa-tacacs with name %s not present in the switch' % name
            )
    else:
        module.fail_json(
            msg='aaa-tacacs action %s not supported. Use create/delete/modify' % action
        )
    
    cli = pn_cli(module)
    cli += action + ' name ' + name
    if action != 'delete':
        if scope:
            cli += ' scope ' + scope

        if server:
            cli += ' server ' + server

        if port:
            cli += ' port ' + port

        if secret:
            cli += ' secret ' + secret

        if priority:
            cli += ' priority ' + priority

        if authen_method:
            cli += ' authen-method ' + authen_method

        if service:
            cli += ' service ' + service

        if service_shell:
            cli += ' service-shell ' + service_shell

        if service_vtysh:
            cli += ' service-vtysh ' + service_vtysh

        cli += ' authen' if authen else ' no-authen'
        cli += ' authen-local' if authen_local else ' no-authen-local'
        cli += ' sess-acct' if sess_acct else ' no-sess-acct'
        cli += ' cmd-acct' if cmd_acct else ' no-cmd-acct'
        cli += ' acct-local' if acct_local else ' no-acct-local'
        cli += ' author-local' if author_local else ' no-author-local'
        cli += ' cmd-author' if cmd_author else ' no-cmd-author'
        cli += ' sess-author' if sess_author else ' no-sess-author'

    run_cli(module, cli)

if __name__ == '__main__':
    main()
