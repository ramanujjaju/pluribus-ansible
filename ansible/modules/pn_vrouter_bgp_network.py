#!/usr/bin/python
""" PN CLI vrouter-bgp-network-add/remove """
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

DOCUMENTATION = """
---
module: pn_vrouter_bgp_network
author: "Pluribus Networks (devops@pluribusnetworks.com)"
version: 2
short_description: CLI command to add/remove vrouter-bgp-network.
description:
  - C(add): add Border Gateway Protocol network to a vRouter
  - C(remove): remove Border Gateway Protocol network from a vRouter
options:
  pn_cliusername:
    description:
      - Provide login username if user is not root.
    required: False
    type: str
  pn_clipassword:
    description:
      - Provide login password if user is not root.
    required: False
    type: str
  pn_cliswitch:
    description:
      - Target switch to run the CLI on.
    required: False
    type: str
  action:
    description:
      - vrouter-bgp-network configuration command.
    required: true
    choices: ['add', 'remove']
    type: str
  pn_netmask:
    description:
      - BGP network mask
    required: false
    type: str
  pn_network:
    description:
      - IP address for BGP network
    required: false
    type: str
  pn_vrouter_name:
    description:
      - name of service config
    required: false
    type: str
"""

EXAMPLES = """
- name: vrouter bgp network module
  pn_vrouter_bgp_network:
    pn_cliusername: "{{ ansible_user }}"
    pn_clipassword: "{{ ansible_ssh_pass }}"
    pn_vrouter_name: "hmplabpsq-we50100-vrouter"
    pn_network: "104.255.61.1"
    pn_netmask: "32"
    action: "add"
"""

RETURN = """
command:
  description: the CLI command run on the target node.
stdout:
  description: set of responses from the vrouter-bgp-network command.
  returned: always
  type: list
stderr:
  description: set of error responses from the vrouter-bgp-network command.
  returned: on error
  type: list
changed:
  description: indicates whether the CLI caused changes on the target.
  returned: always
  type: bool
"""


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

    cli = '/usr/bin/cli --quiet -e '

    if username and password:
        cli += '--user "%s":"%s" ' % (username, password)

    if cliswitch:
        cli += ' switch ' + cliswitch

    return cli


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
            msg="vrouter-bgp-network %s operation failed" % action,
            changed=False
        )

    if out:
        module.exit_json(
            command=' '.join(cli),
            stdout=out.strip(),
            msg="vrouter-bgp-network %s operation completed" % action,
            changed=True
        )

    else:
        module.exit_json(
            command=' '.join(cli),
            msg="vrouter-bgp-network %s operation completed" % action,
            changed=True
        )


def main():
    """ This section is for arguments parsing """
    module = AnsibleModule(
        argument_spec=dict(
            pn_cliusername=dict(required=False, type='str', no_log=True),
            pn_clipassword=dict(required=False, type='str', no_log=True),
            pn_cliswitch=dict(required=False, type='str'),
            action=dict(required=True, type='str', choices=['add', 'remove']),
            pn_netmask=dict(required=False, type='str'),
            pn_network=dict(required=False, type='str'),
            pn_vrouter_name=dict(required=False, type='str'),
        )
    )

    # Accessing the arguments
    mod_action = module.params['action']
    netmask = module.params['pn_netmask']
    network = module.params['pn_network']
    vrouter_name = module.params['pn_vrouter_name']

    # Building the CLI command string
    cli = pn_cli(module)
    cli += 'vrouter-bgp-network-' + mod_action
    if mod_action in ['add', 'remove']:
        if netmask:
            cli += ' netmask ' + netmask
        if network:
            cli += ' network ' + network
        if vrouter_name:
            cli += ' vrouter-name ' + vrouter_name
    run_cli(module, cli)

if __name__ == '__main__':
    main()
