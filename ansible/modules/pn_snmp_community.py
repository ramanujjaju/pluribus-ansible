#!/usr/bin/python
""" PN CLI snmp-community-create/snmp-community-delete/snmp-community-modify """
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

    cli += ' snmp-community-'

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
            msg="snmp-community %s operation failed" % action,
            changed=False
        )

    if out:
        module.exit_json(
            command=' '.join(cli),
            stdout=out.strip(),
            msg="snmp-community %s operation completed" % action,
            changed=True
        )

    else:
        module.exit_json(
            command=' '.join(cli),
            msg="snmp-community %s operation completed" % action,
            changed=True
        )


def check_community(module, community_string):
    cli = pn_cli(module)
    cli += 'show community-string ' + community_string
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
            pn_community_string=dict(required=True, type='str'),
            pn_community_type=dict(required=False, type='str', choices=['read-only', 'read-write']),
        )
    )

    community_string = module.params['pn_community_string']
    action = module.params['pn_action']
    community_type = module.params['pn_community_type']

    if action == 'create':
        if check_community(module, community_string):
            module.fail_json(
                msg='snmp-community with name %s already present in the switch' % community_string
            )
    elif action == 'modify' or action == 'delete':
        if not check_community(module, community_string):
            module.fail_json(
                msg='snmp-community with name %s not present in the switch' % community_string
            )
    else:
        module.fail_json(
            msg='snmp-community action %s not supported. Use create/delete/modify' % action
        )
    
    cli = pn_cli(module)   
    cli += action + ' community-string ' + community_string
    if community_type and action != 'delete':
        cli += ' community-type ' + community_type

    run_cli(module, cli)

if __name__ == '__main__':
    main()
