#!/usr/bin/python
""" PN ZTP vRouter Setup Third Party"""

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
module: pn_ztp_vrouter_setup
author: 'Pluribus Networks (devops@pluribusnetworks.com)'
description: Module to create vrouters.
options:
    pn_switch_list:
      description:
        - Specify list of all switches.
      required: False
      type: list
      default: []
    pn_vrrp_id:
      description:
        - Specify the vrrp id to be assigned.
      required: False
      type: str
    pn_loopback_ip:
      description:
        - Specify loopback ip to be assigned to vrouters.
      required: False
      type: str
"""

EXAMPLES = """
- name: Create Vrouters
  pn_ztp_vrouter_setup:
    pn_switch_list: "{{ groups['switch'] }}"
    pn_vrrp_id: '18'
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

CHANGED_FLAG = []


def run_cli(module, cli):
    """
    Execute the cli command on the target node(s) and returns the output.
    :param module: The Ansible module to fetch input parameters.
    :param cli: The complete cli string to be executed on the target node(s).
    :return: Output or Error msg depending upon the response from cli else None.
    """
    results = []
    cli = shlex.split(cli)
    rc, out, err = module.run_command(cli)

    if out:
        return out
    if err:
        json_msg = {
            'switch': module.params['pn_current_switch'][0],
            'output': u'Operation Failed: {}'.format(' '.join(cli))
        }
        results.append(json_msg)
        module.exit_json(
            unreachable=False,
            failed=True,
            exception=err.strip(),
            summary=results,
            task='Create vrouter',
            msg='Vrouter creation failed',
            changed=False
        )
    else:
        return None


def create_vrouter(module, switch):
    """
    Create a hardware vrouter.
    :param module: The Ansible module to fetch input parameters.
    :param switch: The name of current running switch.
    :return: String describing if vrouter got created or not.
    """
    global CHANGED_FLAG
    output = ''
    vrrp_id = module.params['pn_vrrp_id']
    pn_ospf_redistribute = module.params['pn_ospf_redistribute']
    pn_pim_ssm = module.params['pn_pim_ssm']

    cli = pn_cli(module)
    cli += ' fabric-node-show format fab-name no-show-headers '
    fabric_name = list(set(run_cli(module, cli).split()))[0]
    vnet_name = fabric_name + '-global'

    cli = pn_cli(module)
    cli += ' vrouter-show format name no-show-headers '
    existing_vrouter_names = run_cli(module, cli)

    if existing_vrouter_names is not None:
        existing_vrouter_names = existing_vrouter_names.split()

    new_vrouter = False
    vrouter_name = switch + '-vrouter'

    if (existing_vrouter_names is not None and vrouter_name not in
            existing_vrouter_names):
        new_vrouter = True

    if new_vrouter or existing_vrouter_names is None:
        if pn_pim_ssm == True:
            pim_ssm = 'pim-ssm'
        else:
            pim_ssm = 'none'

        cli = pn_cli(module)
        cli += ' switch %s ' % switch
        cli += ' vrouter-create name %s vnet %s hw-vrrp-id %s enable ' % (
            vrouter_name, vnet_name, vrrp_id)
        cli += ' router-type hardware proto-multi %s ' % pim_ssm
        if pn_ospf_redistribute:
            cli += ' ospf-redistribute %s ' % pn_ospf_redistribute
        if module.params['pn_bgp_as']:
            cli += ' bgp-as %s' % module.params['pn_bgp_as']
        if module.params['pn_bgp_redistribute']:
            cli += ' bgp-redistribute %s' % module.params['pn_bgp_redistribute']
        run_cli(module, cli)
        output = ' %s: Created vrouter with name %s \n' % (switch, vrouter_name)
        CHANGED_FLAG.append(True)

    return output


def assign_loopback_and_router_id(module, loopback_address, current_switch):
    """
    Add loopback interface and router id to vrouters.
    :param module: The Ansible module to fetch input parameters.
    :param loopback_address: The loopback ip to be assigned.
    :param current_switch: The name of current running switch.
    :return: String describing if loopback ip/router id got assigned or not.
    """
    global CHANGED_FLAG
    output = ''

    leaf_list = module.params['pn_leaf_list']
    spine_list = module.params['pn_spine_list']
    address = loopback_address.split('.')
    static_part = str(address[0]) + '.' + str(address[1]) + '.'
    static_part += str(address[2]) + '.'
    vrouter_count = int(address[3].split('/')[0])
    add_loopback = False
    vrouter = current_switch + '-vrouter'
    cli = pn_cli(module)

    switch_list = spine_list + leaf_list
#    if current_switch in spine_list:
#        count = spine_list.index(current_switch)
#    elif current_switch in leaf_list:
#        count = leaf_list.index(current_switch)

    if current_switch in switch_list:
        count = switch_list.index(current_switch)

    if module.params['pn_loopback_ip_v6']:
        add_loopback_v6 = False
        loopback_ipv6 = module.params['pn_loopback_ip_v6']
        ipv6 = loopback_ipv6.split('/')
        subnet_ipv6 = ipv6[1]
        ipv6 = ipv6[0]
        ipv6 = ipv6.split(':')
        if not ipv6[-1]:
            ipv6[-1] = "0"
        host_count_ipv6 = int(ipv6[-1], 16)
        host_count_ipv6 += count
        ipv6[-1] = str(hex(host_count_ipv6)[2:])
        loopback_ipv6_ip = ':'.join(ipv6)

        # Check existing loopback ip v6
        cli = pn_cli(module)
        cli += ' vrouter-loopback-interface-show ip %s ' % loopback_ipv6_ip
        cli += ' format switch no-show-headers '
        existing_vrouter = run_cli(module, cli)
    
        if existing_vrouter is not None:
            existing_vrouter = existing_vrouter.split()
            if vrouter not in existing_vrouter:
                add_loopback_v6 = True
    
        # Add loopback ip v6 if not already exists
        if add_loopback_v6 or existing_vrouter is None:
            cli = pn_cli(module)
            cli += ' vrouter-loopback-interface-add '
            cli += ' vrouter-name %s ip %s ' % (vrouter, loopback_ipv6_ip)
            run_cli(module, cli)
            CHANGED_FLAG.append(True)
            output += '%s: Added loopback ip %s to %s\n' % (current_switch, loopback_ipv6_ip, vrouter)

    count += vrouter_count
    ip = static_part + str(count)

    # Add router id
    cli = pn_cli(module)
    cli += ' vrouter-modify name %s router-id %s ' % (vrouter, ip)
    run_cli(module, cli)
    output += '%s: Added router id %s to %s\n' % (current_switch, ip, vrouter)

    # Check existing loopback ip
    cli = pn_cli(module)
    cli += ' vrouter-loopback-interface-show ip %s ' % ip
    cli += ' format switch no-show-headers '
    existing_vrouter = run_cli(module, cli)

    if existing_vrouter is not None:
        existing_vrouter = existing_vrouter.split()
        if vrouter not in existing_vrouter:
            add_loopback = True

    # Add loopback ip if not already exists
    if add_loopback or existing_vrouter is None:
        cli = pn_cli(module)
        cli += ' vrouter-loopback-interface-add '
        cli += ' vrouter-name %s ip %s ' % (vrouter, ip)
        run_cli(module, cli)
        CHANGED_FLAG.append(True)
        output += '%s: Added loopback ip %s to %s\n' % (current_switch, ip, vrouter)


    return output


def main():
    """ This section is for arguments parsing """
    module = AnsibleModule(
        argument_spec=dict(
            pn_loopback_ip=dict(required=False, type='str', default='109.109.109.3/32'),
            pn_vrrp_id=dict(required=False, type='str', default='18'),
            pn_current_switch=dict(required=False, type='str'),
            pn_spine_list=dict(required=True, type='list'),
            pn_leaf_list=dict(required=True, type='list'),
            pn_pim_ssm=dict(required=False, type='bool'),
            pn_ospf_redistribute=dict(required=False, type='str',
                                      choices=['none', 'static', 'connected',
                                               'rip', 'ospf'],
                                      default='none'),
            pn_bgp_redistribute=dict(required=False, type='str',
                                      choices=['none', 'static', 'connected',
                                               'rip', 'ospf']),
            pn_bgp_as=dict(required=False, type='str'),
            pn_loopback_ip_v6=dict(required=False, type='str'),
        )
    )

    global CHANGED_FLAG
    results = []
    message = ''
    loopback_address = module.params['pn_loopback_ip']
    current_switch = module.params['pn_current_switch']

    # Create vrouters
    message += create_vrouter(module, current_switch)

    # Assign loopback ip to vrouters
    message += assign_loopback_and_router_id(module, loopback_address, current_switch)

    replace_string = current_switch + ': '
    for line in message.splitlines():
        if replace_string in line:
            results.append({
                'switch': current_switch,
                'output': (line.replace(replace_string, '')).strip()
            })

    # Exit the module and return the required JSON.
    module.exit_json(
        unreachable=False,
        msg='Vrouter creation succeeded',
        summary=results,
        exception='',
        failed=False,
        changed=True if True in CHANGED_FLAG else False,
        task='Create vrouter'
    )

if __name__ == '__main__':
    main()
