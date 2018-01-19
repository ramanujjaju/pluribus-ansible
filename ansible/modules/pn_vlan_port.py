#!/usr/bin/python
""" PN CLI vlan-port-add/vlan-port-remove """
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
module: pn_vlan_port
author: 'Pluribus Networks (devops@pluribusnetworks.com)'
version: 2.0
short_description: CLI command to add/remove tagged/untagged ports to VLANs.
description:
  - Execute vlan-port-add or vlan-port-remove command.
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
      - Target switch(es) to run the cli on.
    required: False
    type: str
  pn_action:
    description:
      - The VLAN port action to perform on the switches.
    required: True
    choices: ['add', 'remove']
    type: str
  pn_vlanid:
    description:
      - Specify the VLAN ID.
    type: str
  pn_vlan_range:
    description:
      - Specify a range of VLAN IDs.
    type: str
  pn_vlan_vnet:
    description:
      - VNET for this VLAN.
    type: str
  pn_ports:
    description:
      - Specify the list of ports.
    type: str
  pn_tag_untag:
    description:
      - Specify either tagged or untagged.
    choices: ['tagged', 'untagged']
    type: str
"""

EXAMPLES = """
- name: Add tagged ports
  pn_vlan_port:
    pn_action: 'add'
    pn_vlanid: 1054
    pn_ports: '10,11,12'
    pn_tag_untag: tagged

- name: Add untagged ports to a range of vlans
  pn_vlan_port:
    pn_action: 'add'
    pn_vlanid: '100-105'
    pn_ports: '20,21,31,32'
    pn_tag_untag: untagged

- name: Remove ports from a vlan
  pn_vlan_port:
    pn_action: 'remove'
    pn_vlanid: 100
    pn_ports: '20, 21'
"""

RETURN = """
command:
  description: the CLI command run on the target node.
stdout:
  description: set of responses from the vlan port command.
  returned: always
  type: list
stderr:
  description: set of error responses from the vlan port command.
  returned: on error
  type: list
changed:
  description: Indicates whether the module applied any configurations on the
  target.
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

    if username and password:
        cli = '/usr/bin/cli --quiet --user "%s":"%s" ' % (username, password)
    else:
        cli = '/usr/bin/cli --quiet '

    if cliswitch:
        cli += ' switch ' + cliswitch

    return cli


def run_cli(module, cli):
    """
    Method to execute the cli command on the target node(s) and returns the
    output.
    :param module: The Ansible module to fetch input parameters.
    :param cli: The complete cli string to be executed on the target node(s).
    :return: Output/Error or Success msg depending upon the response from cli.
    """
    action = module.params['pn_action']
    cli = shlex.split(cli)
    rc, out, err = module.run_command(cli)

    # Response in JSON format
    if err:
        module.fail_json(
            command=' '.join(cli),
            stderr=err.strip(),
            msg="vLAN port %s operation failed" % action,
            changed=False
        )

    if out:
        module.exit_json(
            command=' '.join(cli),
            stdout=out.strip(),
            msg="vLAN port %s operation completed" % action,
            changed=True
        )

    else:
        module.exit_json(
            command=' '.join(cli),
            msg="vLAN port %s operation completed" % action,
            changed=True
        )


def main():
    """ This section is for arguments parsing """
    module = AnsibleModule(
        argument_spec=dict(
            pn_cliusername=dict(required=False, type='str', no_log=True),
            pn_clipassword=dict(required=False, type='str', no_log=True),
            pn_cliswitch=dict(required=False, type='str'),
            pn_action=dict(required=True, type='str',
                           choices=['add', 'remove']),
            pn_vlanid=dict(type='str'),
            pn_vlan_range=dict(type='str'),
            pn_vlan_vnet=dict(type='str'),
            pn_ports=dict(type='str'),
            pn_tag_untag=dict(type='str',
                              choices=['tagged', 'untagged'])
        )
    )

    # Accessing the arguments
    action = module.params['pn_action']
    command = 'vlan-port-' + action
    vlanid = module.params['pn_vlanid']
    vlan_range = module.params['pn_vlan_range']
    ports = module.params['pn_ports']
    vlan_vnet = module.params['pn_vlan_vnet']
    tag_untag = module.params['pn_tag_untag']

    cli = pn_cli(module)
    cli += ' ' + command

    if vlanid:
        cli += ' vlan-id ' + vlanid
    if vlan_range:
        cli += ' vlan-range ' + vlan_range
    if ports:
        cli += ' ports ' + ports
    if vlan_vnet:
        cli += ' vlan-vnet ' + vlan_vnet

    if action == 'add':
        if tag_untag:
            cli += ' ' + tag_untag

    run_cli(module, cli)

if __name__ == '__main__':
    main()
