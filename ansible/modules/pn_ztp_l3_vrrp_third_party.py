#!/usr/bin/python
""" PN CLI L3 VRRP THIRD PARTY """

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
from ansible.module_utils.pn_nvos import *

DOCUMENTATION = """
---
module: pn_ztp_l3_vrrp
author: 'Pluribus Networks (devops@pluribusnetworks.com)'
short_description: CLI command to configure VRRP - Layer 3 Setup
description: Virtual Router Redundancy Protocol (VRRP) - Layer 3 Setup
options:
    pn_spine_list:
      description:
        - Specify list of Spine hosts
      required: False
      type: list
    pn_leaf_list:
      description:
        - Specify list of leaf hosts
      required: False
      type: list
    pn_csv_data:
      description:
        - String containing vrrp data parsed from csv file.
      required: False
      type: str
"""

EXAMPLES = """
- name: Configure L3 VRRP
  pn_ztp_l3_vrrp:
    pn_spine_list: "{{ groups['third_party_spine'] }}"
    pn_leaf_list: "{{ groups['leaf'] }}"
    pn_csv_data: "{{ lookup('file', '{{ csv_file }}') }}"
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
    Method to execute the cli command on the target node(s) and returns the
    output.
    :param module: The Ansible module to fetch input parameters.
    :param cli: The complete cli string to be executed on the target node(s).
    :return: Output/Error or Success msg depending upon the response from cli.
    """
    cli = shlex.split(cli)
    rc, out, err = module.run_command(cli)
    results = []
    if out:
        return out

    if err:
        json_msg = {
            'switch': '',
            'output': u'Operation Failed: {}'.format(' '.join(cli))
        }
        results.append(json_msg)
        module.exit_json(
            unreachable=False,
            failed=True,
            exception=err.strip(),
            summary=results,
            task='Configure L3 vrrp',
            msg='L3 vrrp configuration failed',
            changed=False
        )
    else:
        return 'Success'


def create_vlan(module, vlan_id, switch):
    """
    Method to create vlans.
    :param module: The Ansible module to fetch input parameters.
    :param vlan_id: vlan id to be created.
    :param switch: Name of the switch on which vlan creation will be executed.
    :return: String describing if vlan got created or if it already exists.
    """
    global CHANGED_FLAG
    cli = pn_cli(module)
    clicopy = cli
    cli += ' vlan-show format id no-show-headers '
    existing_vlan_ids = run_cli(module, cli).split()
    existing_vlan_ids = list(set(existing_vlan_ids))

    if vlan_id not in existing_vlan_ids:
        cli = clicopy
        cli += ' vlan-create id %s scope fabric ' % vlan_id
        run_cli(module, cli)
        CHANGED_FLAG.append(True)
        return ' %s: Created vlan id %s with scope fabric \n' % (switch,
                                                                 vlan_id)
    else:
        return ''


def create_vrouter_interface(module, switch, vlan_id, vrrp_id,
                             vrrp_priority, list_vips, list_ips):
    """
    Method to add vrouter interface and assign IP to it along with
    vrrp_id and vrrp_priority.
    :param module: The Ansible module to fetch input parameters.
    :param switch: The switch name on which interfaces will be created.
    :param ip: IP address to be assigned to vrouter interface.
    :param vlan_id: vlan_id to be assigned.
    :param vrrp_id: vrrp_id to be assigned.
    :param vrrp_priority: priority to be given(110 for active switch).
    :param ip_count: The value of fourth octet in the ip
    :return: String describing if vrouter interface got added or not.
    """
    global CHANGED_FLAG
    vrouter_name = switch + '-vrouter'
    ospf_area_id = module.params['pn_ospf_area_id']
    addr_type = module.params['pn_addr_type']

    cli = pn_cli(module)
    clicopy = cli
    cli += ' vrouter-interface-show vlan %s ip %s ' % (vlan_id, list_ips[0])
    cli += ' format switch no-show-headers '
    existing_vrouter = run_cli(module, cli).split()
    existing_vrouter = list(set(existing_vrouter))

    if vrouter_name not in existing_vrouter:
        cli = clicopy
        cli += ' switch ' + switch
        cli += ' vrouter-interface-add vrouter-name ' + vrouter_name
        cli += ' ip ' + list_ips[0]
        cli += ' vlan %s if data ' % vlan_id
        if module.params['pn_addr_type'] == 'ipv4_ipv6':
            cli += ' ip2 ' + list_ips[1]
        if module.params['pn_jumbo_frames'] == True:
            cli += ' mtu 9216'
        if module.params['pn_pim_ssm'] == True:
            cli += ' pim-cluster '
        run_cli(module, cli)
        output = ' %s: Added vrouter interface with ip %s' % (
            switch, list_ips[0]
        )
        if module.params['pn_addr_type'] == 'ipv4_ipv6':
            output += ' ip2 %s' % list_ips[1]
        output += ' to %s \n' % vrouter_name
        CHANGED_FLAG.append(True)
    else:
        output = ''

    cli = clicopy
    cli += ' vrouter-interface-show vrouter-name %s ip %s vlan %s ' % (
        vrouter_name, list_ips[0], vlan_id
    )
    cli += ' format nic no-show-headers '
    eth_port = run_cli(module, cli).split()
    eth_port.remove(vrouter_name)

    for ip_vip in list_vips:
        cli = clicopy
        cli += ' vrouter-interface-show vlan %s ip %s vrrp-primary %s ' % (
            vlan_id, ip_vip, eth_port[0]
        )
        cli += ' format switch no-show-headers '
        existing_vrouter = run_cli(module, cli).split()
        existing_vrouter = list(set(existing_vrouter))

        if vrouter_name not in existing_vrouter:
            cli = clicopy
            cli += ' switch ' + switch
            cli += ' vrouter-interface-add vrouter-name ' + vrouter_name
            cli += ' ip ' + ip_vip
            cli += ' vlan %s if data vrrp-id %s ' % (vlan_id, vrrp_id)
            cli += ' vrrp-primary %s vrrp-priority %s ' % (eth_port[0],
                                                           vrrp_priority)
            if module.params['pn_jumbo_frames'] == True:
                cli += ' mtu 9216'
            if module.params['pn_pim_ssm'] == True:
                cli += ' pim-cluster '
            run_cli(module, cli)
            CHANGED_FLAG.append(True)
            output += ' %s: Added vrouter interface with ip %s to %s \n' % (
                switch, ip_vip, vrouter_name
            )

    ipv4 = list_ips[0]

    if ipv4:
        cli = clicopy
        cli += ' vrouter-ospf-show'
        cli += ' network %s format switch no-show-headers ' % ipv4
        already_added = run_cli(module, cli).split()

        if vrouter_name in already_added:
            pass
        else:
            cli = clicopy
            cli += ' vrouter-ospf-add vrouter-name ' + vrouter_name
            cli += ' network %s ospf-area %s' % (ipv4,
                                                 ospf_area_id)

            if 'Success' in run_cli(module, cli):
                output += ' Added OSPF interface %s to %s \n' % (
                    ipv4, vrouter_name
                )
                CHANGED_FLAG.append(True)

    if addr_type == 'ipv4_ipv6':

        ipv6 = list_ips[1]
        cli = clicopy
        cli += 'vrouter-interface-show vrouter-name %s' % vrouter_name
        cli += ' ip2 %s format nic no-show-headers ' % ipv6
        nic = run_cli(module, cli).split()
        nic = list(set(nic))
        nic.remove(vrouter_name)
        nic = nic[0]

        cli = clicopy
        cli += 'vrouter-ospf6-show nic %s format switch no-show-headers ' % nic
        ipv6_vrouter = run_cli(module, cli).split()

        if vrouter_name not in ipv6_vrouter:
            cli = clicopy
            cli += ' vrouter-ospf6-add vrouter-name %s' % vrouter_name
            cli += ' nic %s ospf6-area 0.0.0.0 ' % nic
            run_cli(module, cli)
            output += ' %s: Added OSPF6 nic %s to %s \n' % (
                vrouter_name, nic, vrouter_name
            )
            CHANGED_FLAG.append(True)

    return output


def create_cluster(module, switch, name, node1, node2):
    """
    Method to create a cluster between two switches.
    :param module: The Ansible module to fetch input parameters.
    :param switch: Name of the local switch.
    :param name: The name of the cluster to create.
    :param node1: First node of the cluster.
    :param node2: Second node of the cluster.
    :return: The output of run_cli() method.
    """
    global CHANGED_FLAG
    cli = pn_cli(module)
    clicopy = cli
    cli += ' switch %s cluster-show format name no-show-headers ' % node1
    cluster_list = run_cli(module, cli).split()
    if name not in cluster_list:
        cli = clicopy
        cli += ' switch %s cluster-create name %s ' % (switch, name)
        cli += ' cluster-node-1 %s cluster-node-2 %s ' % (node1, node2)
        if 'Success' in run_cli(module, cli):
            CHANGED_FLAG.append(True)
            return ' %s: Created %s \n' % (switch, name)
    else:
        return ''


def configure_vrrp_for_non_cluster_leafs(module, ip, ip_v6, non_cluster_leaf, vlan_id):
    """
    Method to configure vrrp for non-cluster switches.
    :param module: The Ansible module to fetch input parameters.
    :param ip: IP address for the default gateway
    :param non_cluster_leaf: Name of non-cluster leaf switch.
    :param vlan_id: The vlan id to be assigned.
    :return: String describing whether interfaces got added or not.
    """
    global CHANGED_FLAG
    vrouter_name = non_cluster_leaf + '-vrouter'

    cli = pn_cli(module)
    clicopy = cli
    cli += 'switch ' + non_cluster_leaf
    cli += ' vrouter-interface-show ip %s vlan %s ' % (ip, vlan_id)
    cli += ' format switch no-show-headers '
    existing_vrouter = run_cli(module, cli).split()
    existing_vrouter = list(set(existing_vrouter))

    if vrouter_name not in existing_vrouter:
        cli = clicopy
        cli += 'switch ' + non_cluster_leaf
        cli += ' vrouter-interface-add vrouter-name ' + vrouter_name
        cli += ' vlan ' + vlan_id
        cli += ' ip ' + ip
        if module.params['pn_addr_type'] == 'ipv4_ipv6':
            cli += ' ip2 ' + ip_v6
        if module.params['pn_jumbo_frames'] == True:
            cli += ' mtu 9216'
        if module.params['pn_pim_ssm'] == True:
            cli += ' pim-cluster '
        run_cli(module, cli)
        CHANGED_FLAG.append(True)
        output = ' %s: Added vrouter interface with ip %s' % (
            non_cluster_leaf, ip)
        if module.params['pn_addr_type'] == 'ipv4_ipv6':
            output += ' ip2 %s' % ip_v6
        output += ' to %s \n' % vrouter_name
        return output
    else:
        return ''


def configure_vrrp_for_clustered_switches(module, vrrp_id, vrrp_ip, vrrp_ipv6,
                                          active_switch, vlan_id, switch_list):
    """
    Method to configure vrrp interfaces for clustered leaf switches.
    :param module: The Ansible module to fetch input parameters.
    :param vrrp_id: The vrrp_id to be assigned.
    :param vrrp_ip: The vrrp_ip to be assigned.
    :param active_switch: The name of the active switch.
    :param vlan_id: vlan id to be assigned.
    :param switch_list: List of clustered switches.
    :return: The output of the configuration.
    """
    node1 = switch_list[0]
    node2 = switch_list[1]
    name = node1 + '-to-' + node2 + '-cluster'
    list_vips = []
    addr_type = module.params['pn_addr_type']

    output = create_cluster(module, node2, name, node1, node2)
    output += create_vlan(module, vlan_id, node2)

    list_vips.append(vrrp_ip)
    ip_addr = vrrp_ip.split('.')
    fourth_octet = ip_addr[3].split('/')
    subnet_ipv4 = fourth_octet[1]
    host_count_ipv4 = int(fourth_octet[0])
    static_ip = ip_addr[0] + '.' + ip_addr[1] + '.' + ip_addr[2] + '.'

    if addr_type == 'ipv4_ipv6':
        list_vips.append(vrrp_ipv6)
        ipv6 = vrrp_ipv6.split('/')
        subnet_ipv6 = ipv6[1]
        ipv6 = ipv6[0]
        ipv6 = ipv6.split(':')
        if not ipv6[-1]:
            ipv6[-1] = "0"
        host_count_ipv6 = int(ipv6[-1], 16)

    for switch in switch_list:
        list_ips = []
        host_count_ipv4 = host_count_ipv4 + 1
        vrrp_ipv4 = static_ip + str(host_count_ipv4) + '/' + subnet_ipv4
        list_ips.append(vrrp_ipv4)
        if addr_type == 'ipv4_ipv6':
            host_count_ipv6 = host_count_ipv6 + 1
            ipv6[-1] = str(hex(host_count_ipv6)[2:])
            vrrp_ipv6_ip = ':'.join(ipv6) + '/' + subnet_ipv6
            list_ips.append(vrrp_ipv6_ip)

        vrrp_priority = '110' if switch == active_switch else '100'
        output += create_vrouter_interface(module, switch, vlan_id, vrrp_id,
                                           vrrp_priority, list_vips, list_ips)

    return output


def configure_vrrp_for_non_clustered_switches(module, vlan_id, ip, ip_v6,
                                              non_cluster_leaf):
    """
    Method to configure VRRP for non clustered leafs.
    :param module: The Ansible module to fetch input parameters.
    :param vlan_id: vlan id to be assigned.
    :param ip: Ip address to be assigned.
    :param non_cluster_leaf: Name of non-clustered leaf switch.
    :return: Output string of configuration.
    """
    output = ''
    output += create_vlan(module, vlan_id, non_cluster_leaf)
    output += configure_vrrp_for_non_cluster_leafs(module, ip, ip_v6,
                                                   non_cluster_leaf, vlan_id)
    return output


def configure_vrrp(module, csv_data):
    """
    Method to configure VRRP L3.
    :param module: The Ansible module to fetch input parameters.
    :param csv_data: String containing vrrp data passed from csv file.
    :return: Output string of configuration.
    """
    output = ''
    vrrp_ipv6 = ''

    csv_data = csv_data.strip()
    csv_data_list = csv_data.split('\n')
    # Parse csv file data and configure VRRP.
    for row in csv_data_list:
        row = row.strip()
        if row.startswith('#'):
            continue
        else:
            elements = row.split(',')
            elements = filter(None, elements)
            switch_list = []
            vlan_id = elements.pop(0).strip()
            vrrp_ip = elements.pop(0).strip()
            if module.params['pn_addr_type'] == 'ipv4_ipv6':
                vrrp_ipv6 = elements.pop(0).strip()
            leaf_switch_1 = elements.pop(0).strip()
            if module.params['pn_current_switch'] == leaf_switch_1:
                if len(elements) > 2:
                    leaf_switch_2 = elements.pop(0).strip()
                    vrrp_id = elements.pop(0).strip()
                    active_switch = elements.pop(0).strip()
                    switch_list.append(leaf_switch_1)
                    switch_list.append(leaf_switch_2)
                    output += configure_vrrp_for_clustered_switches(module, vrrp_id,
                                                                    vrrp_ip, vrrp_ipv6,
                                                                    active_switch,
                                                                    vlan_id,
                                                                    switch_list)

                else:
                    output += configure_vrrp_for_non_clustered_switches(
                        module, vlan_id, vrrp_ip, vrrp_ipv6, leaf_switch_1)

    return output


def main():
    """ This section is for arguments parsing """
    module = AnsibleModule(
        argument_spec=dict(
            pn_spine_list=dict(required=False, type='list'),
            pn_leaf_list=dict(required=False, type='list'),
            pn_csv_data=dict(required=True, type='str'),
            pn_current_switch=dict(required=True, type='str'),
            pn_pim_ssm=dict(required=False, type='bool', default=False),
            pn_jumbo_frames=dict(required=False, type='bool', default=False),
            pn_ospf_area_id=dict(required=False, type='str', default='0'),
            pn_addr_type=dict(required=False, type='str',
                              choices=['ipv4', 'ipv6', 'ipv4_ipv6'],
                              default='ipv4'),
        )
    )

    global CHANGED_FLAG
    message = ''
    leaf_list = module.params['pn_leaf_list']

    if module.params['pn_current_switch'] in leaf_list:
        message += configure_vrrp(module, module.params['pn_csv_data'])

    # Exit the module and return the required JSON.
    message_string = message
    results = []
    switch_list = module.params['pn_spine_list'] + leaf_list
    for switch in switch_list:
        replace_string = switch + ': '

        for line in message_string.splitlines():
            if replace_string in line:
                json_msg = {
                    'switch': switch,
                    'output': (line.replace(replace_string, '')).strip()
                }
                results.append(json_msg)

    # Exit the module and return the required JSON.
    module.exit_json(
        unreachable=False,
        task='Configure L3 vrrp',
        msg='L3 third party vrrp configuration succeeded',
        summary=results,
        exception='',
        failed=False,
        changed=True if True in CHANGED_FLAG else False
    )

if __name__ == '__main__':
    main()

